#ifndef __FUSE_CTX_H
#define __FUSE_CTX_H

#define FUSE_USE_VERSION 34

#include <fuse_lowlevel.h>
#include "com_ctx.h"

class sdfs_fuse_ctx final
{
protected:
	struct fuse_args args;
	struct fuse_cmdline_opts opts{};

	struct fuse_session* fse = nullptr;
	bool signal_handlers_set = false;
	bool session_mounted = false;

	com_ctx cctx;

	/* Operations */

	void op_statfs(fuse_req_t req, fuse_ino_t ino);

	static void _op_statfs(fuse_req_t req, fuse_ino_t ino);

	static constexpr struct fuse_lowlevel_ops f_ops = {
		.statfs = _op_statfs,
	};

	/* Callbacks */
	void cb_getattr(fuse_req_t req, req_getattr_result res);

public:
	sdfs_fuse_ctx(int argc, char** argv);
	~sdfs_fuse_ctx();

	void initialize();
	void main();
};

#endif /* __FUSE_CTX_H */
