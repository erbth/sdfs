#define FUSE_USE_VERSION 34

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>
#include <new>
#include <fuse_lowlevel.h>
#include "config.h"
#include "common/exceptions.h"
#include "common/file_config.h"
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

	default:
		return EIO;
	};
}


/* Contexts for individual operations */
struct req_statfs
{
	fuse_req_t req;
	fuse_ino_t ino;

	sdfs::fs_attr_t fs_attr;
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
	static void _op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		g_ctx->op_lookup(req, parent, name);
	}

	void op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		printf("lookup: %lu, %s\n", parent, name);
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_forget(fuse_req_t req, fuse_ino_t ino, uint64_t lookup)
	{
		g_ctx->op_forget(req, ino, lookup);
	}

	void op_forget(fuse_req_t req, fuse_ino_t ino, uint64_t lookup)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		g_ctx->op_getattr(req, ino, fi);
	}

	void op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_mkdir(fuse_req_t req, fuse_ino_t parent, const char* name,
			mode_t mode)
	{
		g_ctx->op_mkdir(req, parent, name, mode);
	}

	void op_mkdir(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_unlink(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		g_ctx->op_unlink(req, parent, name);
	}

	void op_unlink(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		g_ctx->op_unlink(req, parent, name);
	}

	void op_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		g_ctx->op_open(req, ino, fi);
	}

	void op_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			struct fuse_file_info* fi)
	{
		g_ctx->op_read(req, ino, size, off, fi);
	}

	void op_read(fuse_req_t req, fuse_ino_t ino, size_t sizse, off_t off,
			struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size,
			off_t off, struct fuse_file_info* fi)
	{
		g_ctx->op_write(req, ino, buf, size, off, fi);
	}

	void op_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size,
			off_t off, struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		g_ctx->op_release(req, ino, fi);
	}

	void op_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static void _op_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t off, struct fuse_file_info* fi)
	{
		g_ctx->op_readdir(req, ino, size, off, fi);
	}

	void op_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
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


	static void _op_create(fuse_req_t req, fuse_ino_t parent, const char* name,
			mode_t mode, struct fuse_file_info* fi)
	{
		g_ctx->op_create(req, parent, name, mode, fi);
	}

	void op_create(fuse_req_t req, fuse_ino_t parent, const char* name,
			mode_t mode, struct fuse_file_info* fi)
	{
		check_call(fuse_reply_err(req, ENOSYS), "fuse_reply_err");
	}


	static constexpr struct fuse_lowlevel_ops f_ops = {
		.lookup = _op_lookup,
		//.forget = _op_forget,
		//.getattr = _op_getattr,
		//.mkdir = _op_mkdir,
		//.unlink = _op_unlink,
		//.rmdir = _op_rmdir,
		//.open = _op_open,
		//.read = _op_read,
		//.write = _op_write,
		//.release = _op_release,
		//.readdir = _op_readdir,
		.statfs = _op_statfs,
		//.create = _op_create
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
	}

	void build_fuse_args()
	{
		f_argv.push_back("sdfs-fs");

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

		fuse_daemonize(args.fuse_foreground);
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

				args.mountpoint = arg;
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
	ctx_t ctx(args);
	g_ctx = &ctx;

	ctx.initialize();
	ctx.main();
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
