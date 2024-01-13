#include <cstdlib>
#include <stdexcept>
#include "fuse_ctx.h"
#include "common/exceptions.h"

using namespace std;

static sdfs_fuse_ctx* global_sdfs_fuse_ctx = nullptr;


sdfs_fuse_ctx::sdfs_fuse_ctx(int argc, char** argv)
	: args(FUSE_ARGS_INIT(argc, argv))
{
}

sdfs_fuse_ctx::~sdfs_fuse_ctx()
{
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


void sdfs_fuse_ctx::op_statfs(fuse_req_t req, fuse_ino_t ino)
{
	cctx.request_getattr(bind_front(&sdfs_fuse_ctx::cb_getattr, this, req));
}

void sdfs_fuse_ctx::_op_statfs(fuse_req_t req, fuse_ino_t ino)
{
	global_sdfs_fuse_ctx->op_statfs(req, ino);
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

	int ret = fuse_reply_statfs(req, &buf);
	if (ret < 0)
		fprintf(stderr, "fuse_reply_statfs failed: %d\n", ret);
}
