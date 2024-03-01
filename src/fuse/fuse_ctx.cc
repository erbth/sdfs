#include <algorithm>
#include <limits>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include "fuse_ctx.h"
#include "common/exceptions.h"
#include "common/dynamic_buffer.h"

using namespace std;


#define OFFSET_SENTINEL (numeric_limits<off_t>::max())


static sdfs_fuse_ctx* global_sdfs_fuse_ctx = nullptr;

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
	case err::SUCCESS:
		return 0;

	case err::IO:
		return EIO;

	case err::NOENT:
		return ENOENT;

	case err::INVAL:
		return EINVAL;

	case err::NOTDIR:
		return ENOTDIR;

	default:
		return EIO;
	};
}

struct stat generate_st_buf_from_getfattr(
		fuse_req_t req, const prot::client::reply::getfattr& msg)
{
	struct stat s{};

	if (msg.type == prot::client::reply::FT_DIRECTORY)
		s.st_mode = S_IFDIR | 0755;
	else
		s.st_mode = S_IFREG | 0644;

	s.st_nlink = msg.nlink;

	auto fctx = fuse_req_ctx(req);
	s.st_uid = fctx->uid;
	s.st_gid = fctx->gid;

	s.st_size = msg.size;
	s.st_mtim.tv_sec = msg.mtime / 1000000;
	s.st_mtim.tv_nsec = (msg.mtime % 1000000) * 1000;

	return s;
}

struct stat generate_st_buf_from_create(
		fuse_req_t req, const prot::client::reply::create& msg)
{
	struct stat s{};

	s.st_mode = S_IFREG | 0644;
	s.st_nlink = 1;

	auto fctx = fuse_req_ctx(req);
	s.st_uid = fctx->uid;
	s.st_gid = fctx->gid;

	s.st_size = 0;
	s.st_mtim.tv_sec = msg.mtime / 1000000;
	s.st_mtim.tv_nsec = (msg.mtime % 1000000) * 1000;

	return s;
}

inline open_list<file_ctx>::node* get_file_ctx_node(
		struct fuse_file_info* fi, fuse_ino_t ino)
{
	auto fn = reinterpret_cast<open_list<file_ctx>::node*>(fi->fh);
	if (!fn)
		throw invalid_argument("fh of fuse_file_info is nullptr");

	if (fn->elem.ino != ino)
		throw invalid_argument("Inode of open file changed");

	return fn;
}

inline file_ctx& get_file_ctx(struct fuse_file_info* fi, fuse_ino_t ino)
{
	return get_file_ctx_node(fi, ino)->elem;
}


sdfs_fuse_ctx::sdfs_fuse_ctx(int argc, char** argv)
	: args(FUSE_ARGS_INIT(argc, argv))
{
}

sdfs_fuse_ctx::~sdfs_fuse_ctx()
{
	/* Clear open file list */
	while (auto fn = open_files.get_head())
	{
		fprintf(stderr, "WARNING: open_files list not empty! (force umount?)\n");
		open_files.remove(fn);
		delete fn;
	}

	if (fse)
	{
		if (session_mounted)
			fuse_session_unmount(fse);

		if (signal_handlers_set)
			fuse_remove_signal_handlers(fse);

		fuse_session_destroy(fse);
	}

	if (opts.mountpoint)
		free(opts.mountpoint);

	fuse_opt_free_args(&args);
}

void sdfs_fuse_ctx::initialize()
{
	/* Set global ctx */
	if (global_sdfs_fuse_ctx)
		throw runtime_error("initialize called multiple times");

	global_sdfs_fuse_ctx = this;

	if (fuse_parse_cmdline(&args, &opts))
		throw invalid_cmd_args("invalid arguments");

	if (opts.show_help || opts.show_version)
		throw cmd_args_help();

	if (!opts.mountpoint)
		throw invalid_cmd_args("A mountmount is required");

	/* Connect to controllers */
	cctx.initialize();

	/* Create session */
	fse = fuse_session_new(&args, &f_ops, sizeof(f_ops), nullptr);
	if (!fse)
		throw runtime_error("Failed to create fuse session");

	if (fuse_set_signal_handlers(fse))
		throw runtime_error("fuse_set_signal_handlers failed");
	signal_handlers_set = true;

	if (fuse_session_mount(fse, opts.mountpoint))
		throw runtime_error("fuse_session_mount failed");
	session_mounted = true;

	/* NOTE: Not sure who custom threads behave during fuse_daemonize, hence
	 * instantiate them afterwards */
	fuse_daemonize(opts.foreground);

	cctx.start_threads();
}

void sdfs_fuse_ctx::main()
{
	/* Block until signal or fuserumount -u */
	if (opts.singlethread)
	{
		fuse_session_loop(fse);
	}
	else
	{
		struct fuse_loop_config config{};
		config.clone_fd = opts.clone_fd;
		config.max_idle_threads = opts.max_idle_threads;
		fuse_session_loop_mt(fse, &config);
	}
}


void sdfs_fuse_ctx::op_lookup(fuse_req_t req, fuse_ino_t parent,
		const char* name)
{
	cctx.request_readdir(parent, bind_front(&sdfs_fuse_ctx::cb_lookup, this,
				req, parent, name));
}

void sdfs_fuse_ctx::op_getattr(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	cctx.request_getfattr(ino, bind_front(&sdfs_fuse_ctx::cb_getfattr, this,
				req, ino));
}

void sdfs_fuse_ctx::op_readdir(fuse_req_t req, fuse_ino_t ino,
		size_t size, off_t off, struct fuse_file_info* fi)
{
	cctx.request_readdir(ino, bind_front(&sdfs_fuse_ctx::cb_readdir, this,
				req, ino, size, off));
}

void sdfs_fuse_ctx::op_statfs(fuse_req_t req, fuse_ino_t ino)
{
	cctx.request_getattr(bind_front(&sdfs_fuse_ctx::cb_getattr, this, req));
}


void sdfs_fuse_ctx::op_open(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	/* Check flags */
	if ((fi->flags & O_ACCMODE) == 0)
	{
		check_call(fuse_reply_err(req, EINVAL), "fuse_reply_err");
		return;
	}

	/* Check if file exists */
	cctx.request_getfattr(ino, bind_front(&sdfs_fuse_ctx::cb_open,
				this, req, ino, fi));
}

void sdfs_fuse_ctx::op_create(fuse_req_t req, fuse_ino_t parent,
		const char* name, mode_t mode, struct fuse_file_info* fi)
{
	/* Check flags and maximum filename length */
	if ((fi->flags & O_ACCMODE) == 0 || strlen(name) > 255)
	{
		check_call(fuse_reply_err(req, EINVAL), "fuse_reply_err");
		return;
	}

	cctx.request_create(parent, name, bind_front(&sdfs_fuse_ctx::cb_create,
				this, req, fi));
}

void sdfs_fuse_ctx::op_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t off, struct fuse_file_info* fi)
{
	check_call(fuse_reply_err(req, EIO), "fuse_reply_err");
}

void sdfs_fuse_ctx::op_write(fuse_req_t req, fuse_ino_t ino, const char* buf,
		size_t size, off_t off, struct fuse_file_info* fi)
{
	check_call(fuse_reply_err(req, EIO), "fuse_reply_err");
}

void sdfs_fuse_ctx::op_release(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	auto fn = get_file_ctx_node(fi, ino);

	/* Remove file ctx */
	open_files.remove(fn);
	delete fn;

	printf("close(%u)\n", (unsigned) ino);

	check_call(fuse_reply_err(req, 0), "fuse_reply_err");
}


void sdfs_fuse_ctx::_op_lookup(fuse_req_t req, fuse_ino_t parent,
		const char* name)
{
	global_sdfs_fuse_ctx->op_lookup(req, parent, name);
}

void sdfs_fuse_ctx::_op_getattr(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_getattr(req, ino, fi);
}

void sdfs_fuse_ctx::_op_readdir(fuse_req_t req, fuse_ino_t ino,
		size_t size, off_t off, struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_readdir(req, ino, size, off, fi);
}

void sdfs_fuse_ctx::_op_statfs(fuse_req_t req, fuse_ino_t ino)
{
	global_sdfs_fuse_ctx->op_statfs(req, ino);
}

void sdfs_fuse_ctx::_op_open(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_open(req, ino, fi);
}

void sdfs_fuse_ctx::_op_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t off, struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_read(req, ino, size, off, fi);
}

void sdfs_fuse_ctx::_op_write(fuse_req_t req, fuse_ino_t ino, const char* buf,
		size_t size, off_t off, struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_write(req, ino, buf, size, off, fi);
}

void sdfs_fuse_ctx::_op_release(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_release(req, ino, fi);
}

void sdfs_fuse_ctx::_op_create(fuse_req_t req, fuse_ino_t parent,
		const char* name, mode_t mode, struct fuse_file_info* fi)
{
	global_sdfs_fuse_ctx->op_create(req, parent, name, mode, fi);
}


void sdfs_fuse_ctx::cb_lookup(fuse_req_t req, fuse_ino_t parent, const char* name,
		prot::client::reply::readdir& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");
		return;
	}

	/* Try to find entry */
	for (const auto& e : msg.entries)
	{
		if (strcmp(name, e.name.c_str()) == 0)
		{
			/* Query attributes */
			cctx.request_getfattr(
					e.node_id,
					bind_front(&sdfs_fuse_ctx::cb_lookup2, this, req, parent,
						e.node_id));

			return;
		}
	}

	check_call(fuse_reply_err(req, ENOENT), "fuse_reply_err");
}

void sdfs_fuse_ctx::cb_lookup2(fuse_req_t req, fuse_ino_t parent,
		fuse_ino_t ino, prot::client::reply::getfattr& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");
		return;
	}

	auto st_buf = generate_st_buf_from_getfattr(req, msg);
	struct fuse_entry_param ep = {
		.ino = ino,
		.attr = st_buf,
		.attr_timeout = 0,
		.entry_timeout = 0,
	};

	check_call(fuse_reply_entry(req, &ep), "fuse_reply_entry");
}

void sdfs_fuse_ctx::cb_getattr(fuse_req_t req, req_getattr_result res)
{
	/* The allocation size is always divisible by 1 MiB */
	const size_t blksize = 1024 * 1024;

	auto b_free = (res.size_total - res.size_used) / blksize;
	auto i_free = res.inodes_total - res.inodes_used;

	struct statvfs buf = {
		.f_bsize = blksize,
		.f_frsize = blksize,
		.f_blocks = res.size_total / blksize,
		.f_bfree = b_free,
		.f_bavail = b_free,
		.f_files = res.inodes_total,
		.f_ffree = i_free,
		.f_favail = i_free,
		.f_namemax = 255
	};

	check_call(fuse_reply_statfs(req, &buf), "fuse_reply_statfs");
}

void sdfs_fuse_ctx::cb_getfattr(fuse_req_t req, fuse_ino_t ino,
		prot::client::reply::getfattr& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");

		return;
	}

	auto s = generate_st_buf_from_getfattr(req, msg);
	check_call(fuse_reply_attr(req, &s, 0), "fuse_reply_attr");
}

void sdfs_fuse_ctx::cb_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t off, prot::client::reply::readdir& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");
		return;
	}

	/* Sort entries by inode id to get a stable offset order */
	sort(msg.entries.begin(), msg.entries.end(), [](const auto& a, const auto& b) {
			return a.node_id*2 + (a.name == ".." ? 1 : 0) <
					b.node_id*2 + (b.name == ".." ? 1 : 0);
	});

	dynamic_buffer buf;
	size_t bufsz = 0;

	for (auto i = msg.entries.cbegin(); i != msg.entries.cend(); i++)
	{
		auto& e = *i;

		/* This is very hacky and depends on the absence of other hardlinks */
		if ((long int) e.node_id*2 + (e.name == ".." ? 1 : 0) < off)
			continue;

		/* Add directory entry to buffer */
		auto inext = i + 1;
		off_t next_off = inext == msg.entries.cend() ? OFFSET_SENTINEL :
			(inext->node_id*2 + (inext->name == ".." ? 1 : 0));

		struct stat stbuf{};
		stbuf.st_ino = e.node_id;
		stbuf.st_mode = e.type == prot::client::reply::FT_DIRECTORY ? S_IFDIR : S_IFREG;

		auto newsz = bufsz + fuse_add_direntry(
				req, nullptr, 0, e.name.c_str(), &stbuf, next_off);

		if (newsz > size)
			break;

		buf.ensure_size(newsz);

		fuse_add_direntry(
				req, buf.ptr() + bufsz, newsz - bufsz,
				e.name.c_str(), &stbuf, next_off);

		bufsz = newsz;
	}

	if (bufsz > 0)
		check_call(fuse_reply_buf(req, buf.ptr(), bufsz), "fuse_reply_buf");
	else
		check_call(fuse_reply_buf(req, nullptr, 0), "fuse_reply_buf");
}


open_list<file_ctx>::node* sdfs_fuse_ctx::setup_file_struct(
		struct fuse_file_info* fi, fuse_ino_t ino)
{
	auto fn = new open_list<file_ctx>::node();
	auto& f = fn->elem;
	try
	{
		/* Setup file info */
		f.append = fi->flags & O_APPEND;
		f.ino = ino;

		/* Setup fuse_file_info */
		fi->direct_io = 1;
		fi->keep_cache = 0;

		open_files.add(fn);

		try
		{
			fi->fh = reinterpret_cast<uintptr_t>(fn);
			return fn;
		}
		catch (...)
		{
			open_files.remove(fn);
			throw;
		}
	}
	catch (...)
	{
		delete fn;
		throw;
	}
}

void sdfs_fuse_ctx::cb_open(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi, prot::client::reply::getfattr& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");
		return;
	}

	/* File exists */
	if (msg.type != prot::client::reply::FT_FILE)
	{
		/* Not sure if opening a directory needs to be supported at the FS
		 * layer, open of a directory with O_RDONLY is supported by open (2). */
		check_call(fuse_reply_err(req, EISDIR), "fuse_reply_err");
		return;
	}

	auto fn = setup_file_struct(fi, ino);
	try
	{
		check_call(fuse_reply_open(req, fi), "fuse_reply_open");
	}
	catch (...)
	{
		open_files.remove(fn);
		delete fn;
		throw;
	}

	printf("open(%u)\n", (unsigned) ino);
}

void sdfs_fuse_ctx::cb_create(fuse_req_t req, fuse_file_info* fi,
		prot::client::reply::create& msg)
{
	if (msg.res != err::SUCCESS)
	{
		check_call(
				fuse_reply_err(req, convert_error_code(msg.res)),
				"fuse_reply_err");
		return;
	}

	fuse_ino_t ino = msg.node_id;
	struct fuse_entry_param ep = {
		.ino = ino,
		.attr = generate_st_buf_from_create(req, msg),
		.attr_timeout = 0,
		.entry_timeout = 0,
	};

	auto fn = setup_file_struct(fi, ino);
	try
	{
		check_call(fuse_reply_create(req, &ep, fi), "fuse_reply_create");
	}
	catch (...)
	{
		open_files.remove(fn);
		delete fn;
		throw;
	}

	printf("create(%u)\n", (unsigned) ino);
}
