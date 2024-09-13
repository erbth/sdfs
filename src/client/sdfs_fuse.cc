#define FUSE_USE_VERSION 34

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <string>
#include <map>
#include <list>
#include <mutex>
#include <new>
#include <fuse_lowlevel.h>
#include "config.h"
#include "common/exceptions.h"
#include "common/file_config.h"
#include "common/fixed_buffer.h"
#include "common/dynamic_buffer.h"
#include "sdfs_fs_internal.h"

using namespace std;
using namespace std::literals;


struct args_t final
{
	vector<string> portals;
	string mountpoint;

	/* libfuse related options */
	bool fuse_foreground = false;
	bool fuse_allow_other = false;
	bool fuse_allow_root = false;
	bool fuse_auto_unmount = false;
};


struct ctx_t;
static ctx_t* g_ctx = nullptr;

sdfs::FSClient* g_fsc = nullptr;


/* Convert to absolute path */
string resolve_path(const char* p)
{
	auto resolved = realpath(p, nullptr);
	if (!resolved)
		throw system_error(errno, generic_category(), "resolve_path(mountpoint)");

	try
	{
		string s(resolved);
		free(resolved);
		return s;
	}
	catch (...)
	{
		free(resolved);
		throw;
	}
}


inline int check_call(int ret, const char* fn_name)
{
	if (ret < 0)
		fprintf(stderr, "%s failed: %d\n", fn_name, ret);

	return ret;
}

int convert_error_code(int c)
{
	switch (c)
	{
	case sdfs::err::SUCCESS:
		return 0;

	case sdfs::err::IO:
		return EIO;

	case sdfs::err::NOENT:
		return ENOENT;

	case sdfs::err::INVAL:
		return EINVAL;

	case sdfs::err::NOTDIR:
		return ENOTDIR;

	case sdfs::err::NOSPC:
		return ENOSPC;

	case sdfs::err::NAMETOOLONG:
		return ENAMETOOLONG;

	case sdfs::err::ISDIR:
		return EISDIR;

	case sdfs::err::NXIO:
		return ENXIO;

	case sdfs::err::NOTEMPTY:
		return ENOTEMPTY;

	default:
		return EIO;
	};
}


void adapt_user_group(fuse_req_t req, struct stat& st_buf)
{
	auto fctx = fuse_req_ctx(req);
	st_buf.st_uid = fctx->uid;
	st_buf.st_gid = fctx->gid;
}


/* Keeping track of inode lookup count
 *
 * NOTE: on unmount, not all lookup counts are brought to zero using forget().
 * Hence dangling inodes may not be removed in this case, leading to an inode
 * leak in these cases. */
void cb_free_inode(sdfs::async_handle_t, int res, void* arg)
{
	unsigned long ino = (uintptr_t) arg;

	if (res != sdfs::err::SUCCESS)
	{
		throw runtime_error(
				"Failed to free inode " + to_string(ino) + ": " +
				sdfs::error_to_str(res));
	}
}

class InodeReferenceCounter final
{
protected:
	mutex m;

	struct counter_t
	{
		size_t count = 0;
		bool free_on_zero = false;
	};

	map<unsigned long, counter_t> counters;

public:
	void increment(unsigned long ino, size_t count = 1)
	{
		unique_lock lk(m);

		auto i = counters.find(ino);
		if (i == counters.end())
		{
			bool inserted;
			tie(i, inserted) = counters.insert({ino, counter_t()});
		}

		i->second.count += count;
	}

	void decrement(unsigned long ino, size_t count = 1)
	{
		unique_lock lk(m);
		auto i = counters.find(ino);
		if (i == counters.end())
			throw runtime_error("Attempted to decrement unknown inode's lookup count");

		if (i->second.count < count)
			throw runtime_error("Attempted to decrement an inode's lookup count below zero");

		i->second.count -= count;

		if (i->second.count == 0)
		{
			if (i->second.free_on_zero)
			{
				/* Free inode */
				g_fsc->free_inode_explicit(ino, cb_free_inode,
						reinterpret_cast<void*>((uintptr_t) ino));
			}

			counters.erase(i);
		}
	}

	void free(unsigned long ino)
	{
		unique_lock lk(m);
		auto i = counters.find(ino);
		if (i != counters.end())
			i->second.free_on_zero = true;
		else
			g_fsc->free_inode_explicit(ino, cb_free_inode,
					reinterpret_cast<void*>((uintptr_t) ino));
	}
};

InodeReferenceCounter inode_ref_counter;


/* Per opened file data */
struct file_data_t
{
	bool append = false;
};

mutex m_file_data_list;
list<file_data_t> file_data_list;

inline file_data_t* get_file_data(struct fuse_file_info* fi)
{
	return reinterpret_cast<file_data_t*>(fi->fh);
}

inline file_data_t* create_file_data()
{
	unique_lock lk(m_file_data_list);
	return &file_data_list.emplace_back();
}

inline void remove_file_data(file_data_t* fd)
{
	unique_lock lk(m_file_data_list);

	for (auto i = file_data_list.begin(); i != file_data_list.end(); i++)
	{
		if (&(*i) == fd)
		{
			file_data_list.erase(i);
			return;
		}
	}
}


/* Contexts for individual operations */
struct req_unlink
{
	fuse_req_t req;
	unsigned long ino;
};


struct req_lookup
{
	fuse_req_t req;

	struct fuse_entry_param fep{};
};

struct req_getattr
{
	fuse_req_t req;

	struct stat st_buf{};
};


struct req_mkdir
{
	fuse_req_t req;

	struct fuse_entry_param fep{};
};


struct req_readdir
{
	fuse_req_t req;
	size_t size;
	off_t off;

	vector<sdfs::dir_entry_t> entries;
	vector<sdfs::dir_entry_t>::iterator i_entry;
	struct stat st_buf{};

	dynamic_buffer output_buf;
	size_t output_off = 0;
};

struct req_statfs
{
	fuse_req_t req;
	fuse_ino_t ino;

	sdfs::fs_attr_t fs_attr;
};


struct req_create
{
	fuse_req_t req;

	struct fuse_entry_param fep{};
	struct fuse_file_info fi;
};

struct req_open
{
	fuse_req_t req;

	struct fuse_file_info fi;
};


struct req_io
{
	fuse_req_t req;

	size_t act_size{};
	fixed_buffer buf;
};


/* FUSE context */
struct ctx_t final
{
	args_t& args;
	sdfs::FSClient fsc;

	struct fuse_session* fse = nullptr;
	bool session_mounted = false;
	bool signal_handlers_set = false;

	vector<string> f_argv;
	vector<const char*> f_argv_array;
	struct fuse_args f_args{};

	/* Operations */
	static void _op_init(void* userdata, struct fuse_conn_info* conn)
	{
		/* Allow for extensive async io */
		conn->max_background = 128;
	}


	static void _cb_op_lookup(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_lookup*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			auto node_id = int_req->fep.attr.st_ino;

			adapt_user_group(int_req->req, int_req->fep.attr);
			int_req->fep.ino = int_req->fep.attr.st_ino;

			inode_ref_counter.increment(node_id);

			try
			{
				check_call(fuse_reply_entry(int_req->req, &int_req->fep),
						"fuse_reply_entry");
			}
			catch (...)
			{
				inode_ref_counter.decrement(node_id);
				throw;
			}
		}

		delete int_req;
	}

	static void _op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		auto int_req = new req_lookup();
		int_req->req = req;

		g_ctx->fsc.lookup(parent, name, &int_req->fep.attr,
				_cb_op_lookup, int_req);
	}


	static void _op_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
	{
		inode_ref_counter.decrement(ino, nlookup);
		fuse_reply_none(req);
	}


	static void _cb_op_getattr(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_getattr*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			adapt_user_group(int_req->req, int_req->st_buf);
			check_call(fuse_reply_attr(int_req->req, &int_req->st_buf, 0),
					"fuse_reply_attr");
		}

		delete int_req;
	}

	static void _op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		auto int_req = new req_getattr();
		int_req->req = req;

		g_ctx->fsc.getattr(ino, int_req->st_buf, _cb_op_getattr, int_req);
	}


	static void _cb_op_mkdir(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_mkdir*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			auto node_id = int_req->fep.attr.st_ino;

			adapt_user_group(int_req->req, int_req->fep.attr);
			int_req->fep.ino = int_req->fep.attr.st_ino;

			inode_ref_counter.increment(node_id);

			try
			{
				check_call(fuse_reply_entry(int_req->req, &int_req->fep),
						"fuse_reply_entry");
			}
			catch (...)
			{
				inode_ref_counter.decrement(node_id);
				throw;
			}
		}

		delete int_req;
	}

	static void _op_mkdir(fuse_req_t req, fuse_ino_t parent, const char* name,
			mode_t mode)
	{
		auto int_req = new req_mkdir();
		int_req->req = req;

		g_ctx->fsc.mkdir(parent, name, int_req->fep.attr, _cb_op_mkdir, int_req);
	}


	static void _cb_op_unlink(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_unlink*>(arg);

		check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
				"fuse_reply_err");

		auto node_id = int_req->ino;
		delete int_req;

		if (res == sdfs::err::SUCCESS)
			inode_ref_counter.free(node_id);
	}

	static void _op_unlink(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		auto int_req = new req_unlink();
		int_req->req = req;

		g_ctx->fsc.unlink(parent, name, false, &int_req->ino, _cb_op_unlink, int_req);
	}


	static void _cb_op_rmdir(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_unlink*>(arg);

		check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
				"fuse_reply_err");

		auto node_id = int_req->ino;
		delete int_req;

		if (res == sdfs::err::SUCCESS)
			inode_ref_counter.free(node_id);
	}

	static void _op_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		auto int_req = new req_unlink();
		int_req->req = req;

		g_ctx->fsc.rmdir(parent, name, false, &int_req->ino, _cb_op_rmdir, int_req);
	}


	static void _cb_op_open(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_open*>(arg);
		auto req = int_req->req;
		auto fi = int_req->fi;
		delete int_req;

		if (res == sdfs::err::SUCCESS)
		{
			auto fd = create_file_data();
			fd->append = fi.flags & O_APPEND;
			fi.fh = reinterpret_cast<intptr_t>(fd);

			check_call(fuse_reply_open(req, &fi), "fuse_reply_open");
		}
		else
		{
			check_call(fuse_reply_err(req, convert_error_code(res)),
					"fuse_reply_err");
		}
	}

	static void _op_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		fi->fh = 0;
		fi->direct_io = true;
		fi->keep_cache = false;

		if (fi->flags & O_TRUNC)
		{
			auto int_req = new req_open();
			int_req->req = req;
			int_req->fi = *fi;

			g_ctx->fsc.truncate(ino, _cb_op_open, int_req);
		}
		else
		{
			auto fd = create_file_data();
			fd->append = fi->flags & O_APPEND;
			fi->fh = reinterpret_cast<intptr_t>(fd);

			check_call(fuse_reply_open(req, fi), "fuse_reply_open");
		}
	}


	static void _cb_op_read(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_io*>(arg);

		try
		{
			if (res != sdfs::err::SUCCESS)
			{
				check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
						"fuse_reply_err");
			}
			else
			{
				check_call(fuse_reply_buf(int_req->req, int_req->buf.ptr(), int_req->act_size),
						"fuse_reply_buf");
			}
		}
		catch (...)
		{
			delete int_req;
			throw;
		}

		delete int_req;
	}

	static void _op_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			struct fuse_file_info* fi)
	{
		auto int_req = new req_io();

		int_req->req = req;
		int_req->buf = fixed_buffer(size);

		g_ctx->fsc.read(ino, off, size, int_req->act_size, int_req->buf.ptr(),
				_cb_op_read, int_req);
	}


	static void _cb_op_write(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_io*>(arg);
		auto req = int_req->req;
		auto size = int_req->act_size;
		delete int_req;

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			check_call(fuse_reply_write(req, size), "fuse_reply_write");
		}
	}

	static void _op_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size,
			off_t off, struct fuse_file_info* fi)
	{
		auto int_req = new req_io();

		int_req->req = req;
		int_req->buf = fixed_buffer(size);
		int_req->act_size = size;

		memcpy(int_req->buf.ptr(), buf, size);

		/* Handle O_APPEND */
		if (get_file_data(fi)->append)
			off = -1;

		g_ctx->fsc.write(ino, off, size, int_req->buf.ptr(), _cb_op_write, int_req);
	}


	static void _op_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		remove_file_data(get_file_data(fi));
		check_call(fuse_reply_err(req, 0), "fuse_reply_err");
	}


	static void _cb_op_readdir2(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_readdir*>(arg);

		if (res != sdfs::err::SUCCESS && res != sdfs::err::NOENT)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
						"fuse_reply_err");

			delete int_req;
			return;
		}

		/* Add entry to output buffer */
		if (res != sdfs::err::NOENT)
		{
			adapt_user_group(int_req->req, int_req->st_buf);

			auto i_next = int_req->i_entry;
			i_next++;

			auto next_off =
				i_next == int_req->entries.end() ?
					numeric_limits<off_t>::max() :
					i_next->ino;

			/* Determine entry size and check if it exceeds the requested
			 * maximum size */
			auto e_size = fuse_add_direntry(
					int_req->req,
					int_req->output_buf.ptr() + int_req->output_off,
					0,
					int_req->i_entry->name.c_str(),
					&int_req->st_buf,
					next_off);

			auto new_size = int_req->output_off + e_size;
			if (new_size > int_req->size)
			{
				/* Return the current buffer or error if it is still empty */
				if (int_req->output_off == 0)
				{
					check_call(fuse_reply_err(int_req->req, EINVAL), "fuse_reply_err");
				}
				else
				{
					check_call(fuse_reply_buf(int_req->req,
								int_req->output_buf.ptr(), int_req->output_off),
							"fuse_reply_buf");
				}

				delete int_req;
				return;
			}

			int_req->output_buf.ensure_size(new_size);

			/* Serialize entry */
			fuse_add_direntry(
					int_req->req,
					int_req->output_buf.ptr() + int_req->output_off,
					new_size,
					int_req->i_entry->name.c_str(),
					&int_req->st_buf,
					next_off);

			int_req->output_off = new_size;
		}

		/* If another entry is present, read its attributes */
		if (++int_req->i_entry != int_req->entries.end())
		{
			g_ctx->fsc.getattr(int_req->i_entry->ino, int_req->st_buf,
					_cb_op_readdir2, int_req);
		}
		else
		{
			/* Return buffer */
			check_call(fuse_reply_buf(int_req->req,
						int_req->output_buf.ptr(), int_req->output_off),
					"fuse_reply_buf");

			delete int_req;
			return;
		}
	}

	static void _cb_op_readdir(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_readdir*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
						"fuse_reply_err");

			delete int_req;
			return;
		}

		/* Order the entries by name to obtain a stable order for the offset
		 * field */
		sort(int_req->entries.begin(), int_req->entries.end(),
				[](auto& a, auto& b){ return a.name < b.name; });

		/* Skip over entries */
		auto i = int_req->entries.begin();
		if (int_req->off != 0)
			for (; i != int_req->entries.end() && i->ino != (unsigned long) int_req->off; i++);

		int_req->entries.erase(int_req->entries.begin(), i);

		/* End of directory - this can happen at this point if the directory is
		 * modified during the read operation */
		if (int_req->entries.empty())
		{
			check_call(fuse_reply_buf(int_req->req, nullptr, 0), "fuse_reply_buf");
			delete int_req;
			return;
		}

		/* Read entry types */
		int_req->i_entry = int_req->entries.begin();
		g_ctx->fsc.getattr(int_req->i_entry->ino, int_req->st_buf,
				_cb_op_readdir2, int_req);
	}

	static void _op_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t off, struct fuse_file_info* fi)
	{
		if (off == numeric_limits<off_t>::max())
		{
			/* End of directory */
			check_call(fuse_reply_buf(req, nullptr, 0), "fuse_reply_buf");
			return;
		}

		auto int_req = new req_readdir();
		int_req->req = req;
		int_req->size = size;
		int_req->off = off;

		g_ctx->fsc.readdir(ino, int_req->entries, _cb_op_readdir, int_req);
	}


	static void _cb_op_statfs(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_statfs*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			/* The allocation size is always divisible by 1 MiB */
			const size_t blksize = 1024 * 1024;

			auto& fs_attr = int_req->fs_attr;

			auto b_free = (fs_attr.size - fs_attr.used) / blksize;
			auto i_free = fs_attr.inodes - fs_attr.inodes_used;

			struct statvfs buf = {
				.f_bsize = blksize,
				.f_frsize = blksize,
				.f_blocks = fs_attr.size / blksize,
				.f_bfree = b_free,
				.f_bavail = b_free,
				.f_files = fs_attr.inodes,
				.f_ffree = i_free,
				.f_favail = i_free,
				.f_namemax = 255
			};

			check_call(fuse_reply_statfs(int_req->req, &buf), "fuse_reply_statfs");
		}

		delete int_req;
	}

	static void _op_statfs(fuse_req_t req, fuse_ino_t ino)
	{
		auto int_req = new req_statfs();
		int_req->req = req;
		int_req->ino = ino;

		g_ctx->fsc.getfsattr(&int_req->fs_attr, _cb_op_statfs, int_req);
	}

	void op_statfs(fuse_req_t req, fuse_ino_t ino)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _cb_op_create(sdfs::async_handle_t handle, int res, void* arg)
	{
		auto int_req = reinterpret_cast<req_create*>(arg);

		if (res != sdfs::err::SUCCESS)
		{
			check_call(fuse_reply_err(int_req->req, convert_error_code(res)),
					"fuse_reply_err");
		}
		else
		{
			auto node_id = int_req->fep.attr.st_ino;

			adapt_user_group(int_req->req, int_req->fep.attr);

			auto fd = create_file_data();
			fd->append = int_req->fi.flags & O_APPEND;
			int_req->fi.fh = reinterpret_cast<intptr_t>(fd);

			int_req->fi.direct_io = true;
			int_req->fi.keep_cache = false;

			int_req->fep.ino = int_req->fep.attr.st_ino;

			inode_ref_counter.increment(node_id);

			try
			{
				check_call(fuse_reply_create(int_req->req, &int_req->fep, &int_req->fi),
						"fuse_reply_create");
			}
			catch (...)
			{
				inode_ref_counter.decrement(node_id);
				throw;
			}
		}

		delete int_req;
	}

	static void _op_create(fuse_req_t req, fuse_ino_t parent, const char* name,
			mode_t mode, struct fuse_file_info* fi)
	{
		auto int_req = new req_create();
		int_req->req = req;
		int_req->fi = *fi;

		g_ctx->fsc.create(parent, name, int_req->fep.attr, _cb_op_create, int_req);
	}


	static constexpr struct fuse_lowlevel_ops f_ops = {
		.init = _op_init,
		.lookup = _op_lookup,
		.forget = _op_forget,
		.getattr = _op_getattr,
		.mkdir = _op_mkdir,
		.unlink = _op_unlink,
		.rmdir = _op_rmdir,
		.open = _op_open,
		.read = _op_read,
		.write = _op_write,
		.release = _op_release,
		.readdir = _op_readdir,
		.statfs = _op_statfs,
		.create = _op_create
	};


	ctx_t(args_t& args)
		: args(args), fsc(args.portals)
	{
	}

	~ctx_t()
	{
		if (fse)
		{
			if (session_mounted)
				fuse_session_unmount(fse);

			if (signal_handlers_set)
				fuse_remove_signal_handlers(fse);

			fuse_session_destroy(fse);
		}

		fuse_opt_free_args(&f_args);
	}

	void build_fuse_args()
	{
		f_argv.push_back("sdfs-fuse");

		if (args.fuse_allow_other)
			f_argv.push_back("-oallow_other");

		if (args.fuse_allow_root)
			f_argv.push_back("-oallow_root");

		if (args.fuse_auto_unmount)
			f_argv.push_back("-oauto_unmount");

		f_args.allocated = 0;
		f_args.argc = f_argv.size();

		for (auto& e : f_argv)
			f_argv_array.push_back(e.c_str());

		f_args.argv = (char**) f_argv_array.data();
	}

	void initialize()
	{
		/* Build fuse_args */
		build_fuse_args();

		/* Create session */
		fse = fuse_session_new(&f_args, &f_ops, sizeof(f_ops), nullptr);
		if (!fse)
			throw runtime_error("Failed to create fuse session");

		if (fuse_set_signal_handlers(fse))
			throw runtime_error("fuse_set_signal_handlers failed");
		signal_handlers_set = true;

		if (fuse_session_mount(fse, args.mountpoint.c_str()))
			throw runtime_error("fuse_session_mount failed");
		session_mounted = true;
	}

	void main()
	{
		struct fuse_loop_config config{};
		config.clone_fd = false;
		config.max_idle_threads = 4;
		fuse_session_loop_mt(fse, &config);
	}
};


/* Parsing commandline arguments */
args_t parse_args(int argc, char** argv)
{
	args_t args;

	int state = 0;

	for (int i = 1; i < argc; i++)
	{
		auto arg = argv[i];
		auto arglen = strlen(arg);

		switch (state)
		{
		case 0:
			if (arglen >= 2 && strncmp(arg, "--", 2) == 0)
			{
				if (strcmp(arg, "--help") == 0)
					throw cmd_args_help();
				else if (strcmp(arg, "--portal") == 0)
					state = 1000;
				else
					throw invalid_cmd_args("Invalid option `"s + arg + "'"s);
			}
			else if (arglen == 2 && arg[0] == '-')
			{
				if (arg[1] == 'f')
				{
					if (args.fuse_foreground)
						throw invalid_cmd_args("`-f' specified more than once");

					args.fuse_foreground = true;
				}
				else if (arg[1] == 'o')
				{
					state = 1001;
				}
				else
				{
					throw invalid_cmd_args("Invalid short option `"s + arg + "'"s);
				}
			}
			else if (arglen != 2 && arg[0] == '-')
			{
				throw invalid_cmd_args("Invalid short option: `"s + arg + "'"s);
			}
			else if (arglen >= 1)
			{
				if (args.mountpoint.size())
					throw invalid_cmd_args("Multiple mountpoints given");

				/* Convert to absolute path */
				args.mountpoint = resolve_path(arg);
			}
			else
			{
				throw invalid_cmd_args("Empty argument supplied");
			}
			break;

		case 1000:
			args.portals.push_back(arg);
			state = 0;
			break;

		case 1001:
			if (strcmp(arg, "allow_other") == 0)
			{
				if (args.fuse_allow_other)
					throw invalid_cmd_args("`-o allow_other' specified more than once");
				args.fuse_allow_other = true;
			}
			else if (strcmp(arg, "allow_root") == 0)
			{
				if (args.fuse_allow_root)
					throw invalid_cmd_args("`-o allow_root' specified more than once");
				args.fuse_allow_root = true;
			}
			else if (strcmp(arg, "auto_unmount") == 0)
			{
				if (args.fuse_auto_unmount)
					throw invalid_cmd_args("`-o auto_unmount' specified more than once");
				args.fuse_auto_unmount = true;
			}
			else
			{
				throw invalid_cmd_args("Invalid option: `-o "s + arg + "'"s);
			}
			state = 0;
			break;

		default:
			throw runtime_error("Error while parsing arguments");
		}
	}

	if (state != 0)
		throw invalid_cmd_args("Option requires an argument");

	if (args.mountpoint.size() == 0)
		throw invalid_cmd_args("A mountpoint is required");

	if (args.portals.empty())
	{
		/* Read portals from config file */
		auto cfg = read_sdfs_config_file();
		for (auto& p : cfg.portals)
			args.portals.push_back(p);
	}

	return args;
}

void print_help()
{
	fprintf(stderr, R"help(SDFS fuse client of SDFS version %d.%d.%d
FUSE library version: %s

    usage: sdfs-fuse [options] <mountpoint>

The following options are available:
    --portal                 Specify a portal; multiple portals may be specified
                             for multipathing; if no portals are given, the
                             portals specified in the config file are used.

    --help                   Display this help text

  libfuse specific settings:
    -f                       Foreground operation

    -o allow_other           Allow access by all users

    -o allow_root            Allow access by root

    -o auto_unmount          Auto unmount on process termination
)help",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH,
			fuse_pkgversion());
}


void main_exc(args_t args)
{
	/* Fork to background before starting client threads */
	fuse_daemonize(args.fuse_foreground);

	ctx_t ctx(args);
	g_ctx = &ctx;
	g_fsc = &g_ctx->fsc;

	ctx.initialize();
	ctx.main();

	/* Ensure that no asynchronous callbacks will happen after this point */
	g_ctx = nullptr;
	g_fsc = nullptr;
}


int main(int argc, char** argv)
{
	try
	{
		main_exc(parse_args(argc, argv));
	}
	catch (const invalid_cmd_args& e)
	{
		fprintf(stderr, "%s\n", e.what());
		return EXIT_FAILURE;
	}
	catch (const cmd_args_help&)
	{
		print_help();
		return EXIT_FAILURE;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "Error: %s\n", e.what());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
