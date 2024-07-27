/* The public interface provides a wrapper object; this header defines the
 * 'real' implementation. */
#ifndef __SDFS_FS_INTERNAL_H
#define __SDFS_FS_INTERNAL_H

#include <list>
#include <atomic>
#include <functional>
#include "sdfs_ds_internal.h"
#include "sdfs_fs.h"
#include "fs_utils.h"
#include "common/fixed_buffer.h"


class FSClient;


struct allocator_t
{
	fixed_buffer buf;

	size_t count_allocated();
};


struct request_t
{
	std::list<request_t>::iterator i_list;
	FSClient* fsc{};

	allocator_t inode_allocator;
	allocator_t block_allocator;

	std::atomic<unsigned> finished_reqs{0};
	bool io_error{false};

	/* Destination buffer */
	union
	{
		sdfs::fs_attr_t* fs_attr;
		struct stat* st_buf;
		std::vector<sdfs::dir_entry_t>* dir_entries;
	};

	/* Arguments */
	std::string name;

	/* Other data needed for requests */
	std::vector<inode_t> inodes;

	uint64_t handle{};
	sdfs::cb_async_finished_t cb_finished{};
	void* cb_finished_arg{};
};


class FSClient final
{
protected:
	using cb_dsio_t = std::function<void(request_t*)>;

	struct cb_dsio_req_patch
	{
		cb_dsio_t cb;
		request_t* req;
	};

	struct cb_read_inode_ctx : public cb_dsio_req_patch
	{
		unsigned long node_id;
		inode_t* node;
		char buf[4096];
	};

	sdfs::DSClient dsc;

	size_t raw_size = 0;

	superblock_t sb;

	/* Client requests */
	std::mutex m_requests;
	std::list<request_t> requests;

	std::atomic<uint64_t> next_handle{0};

	request_t* add_request();
	void remove_request(request_t*);
	void finish_request(request_t*, int res);

	void read_block_allocator(allocator_t&, cb_dsio_t, request_t*);
	void read_inode_allocator(allocator_t&, cb_dsio_t, request_t*);
	void read_inode(unsigned long node_id, inode_t&, cb_dsio_t, request_t*);

	static void cb_read_inode_allocator(size_t handle, int res, void* arg);
	static void cb_read_inode(size_t handle, int read, void* arg);


	/* Callbacks for fs operations */
	void cb_getfsattr(request_t* req);
	void cb_lookup(request_t* req);
	void cb_lookup2(request_t* req);
	void cb_getattr(request_t* req);
	void cb_readdir(request_t* req);

public:
	FSClient(const std::vector<std::string>& srv_portals);
	~FSClient();

	sdfs::async_handle_t getfsattr(sdfs::fs_attr_t* dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t lookup(
			unsigned long parent_ino, const char* name, struct stat* dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t getattr(unsigned long ino, struct stat& dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t readdir(unsigned long ino, std::vector<sdfs::dir_entry_t>& dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);
};

#endif /* __SDFS_FS_INTERNAL_H */
