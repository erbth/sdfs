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

	void op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name);
	void op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
	void op_readdir(fuse_req_t req, fuse_ino_t ino,
			size_t size, off_t off, struct fuse_file_info* fi);

	void op_statfs(fuse_req_t req, fuse_ino_t ino);

	static void _op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name);
	static void _op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
	static void _op_readdir(fuse_req_t req, fuse_ino_t ino,
			size_t size, off_t off, struct fuse_file_info* fi);

	static void _op_statfs(fuse_req_t req, fuse_ino_t ino);

	static constexpr struct fuse_lowlevel_ops f_ops = {
		.lookup = _op_lookup,
		.getattr = _op_getattr,
		.readdir = _op_readdir,
		.statfs = _op_statfs
	};

	/* Callbacks */
	void cb_lookup(fuse_req_t req, fuse_ino_t parent, const char* name,
			prot::client::reply::readdir& msg);

	void cb_lookup2(fuse_req_t req, fuse_ino_t parent, fuse_ino_t ino,
			prot::client::reply::getfattr& msg);

	void cb_getattr(fuse_req_t req, req_getattr_result res);
	void cb_getfattr(fuse_req_t req, fuse_ino_t ino, prot::client::reply::getfattr& msg);
	void cb_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			prot::client::reply::readdir& msg);

public:
	sdfs_fuse_ctx(int argc, char** argv);
	~sdfs_fuse_ctx();

	void initialize();
	void main();
};

#endif /* __FUSE_CTX_H */
