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

	inline bool is_free(size_t e)
	{
		auto b = e / 8;
		auto msk = 1 << (e % 8);

		return (buf.ptr()[b] & msk) == 0;
	}

	inline void mark_allocated(size_t e)
	{
		auto b = e / 8;
		auto msk = 1 << (e % 8);

		buf.ptr()[b] |= msk;
	}

	inline void mark_free(size_t e)
	{
		auto b = e / 8;
		auto msk = 1 << (e % 8);

		buf.ptr()[b] &= ~msk;
	}
};


struct request_t
{
	std::list<request_t>::iterator i_list;
	FSClient* fsc{};

	allocator_t inode_allocator;
	allocator_t block_allocator;

	/* NOTE: The use of this with a simple .load does not guarantee a
	 * race-condition free execution order if multiple operations of the same
	 * request are performed concurrently. However one can instead use fetch_add
	 * to check for completion and compare with twice the count of operations
	 * (-1 because fetch_add atomically returns the value immediately before the
	 * operation). */
	std::atomic<unsigned> finished_reqs{0};
	bool io_error{false};

	/* Destination buffer */
	union
	{
		sdfs::fs_attr_t* fs_attr;
		struct stat* st_buf;
		std::vector<sdfs::dir_entry_t>* dir_entries;
		unsigned long* dst_ino;
	};

	/* Arguments */
	std::string name;
	bool auto_free_inode{false};

	/* Other data needed for requests */
	std::list<inode_t> inodes;

	uint64_t handle{};
	sdfs::cb_async_finished_t cb_finished{};
	void* cb_finished_arg{};
};


class FSClient final
{
protected:
	using cb_dsio_t = std::function<void(request_t*)>;
	using cb_err_t = std::function<void(int ret, request_t*)>;

	struct cb_dsio_req_patch
	{
		cb_dsio_t cb;
		request_t* req;
	};

	struct cb_inode_ctx : public cb_dsio_req_patch
	{
		unsigned long node_id;
		inode_t* node;
		char buf[4096];
	};

	struct cb_allocate_inode_ctx
	{
		cb_err_t cb;
		unsigned long* node_id;
		unsigned long new_id = 0;
	};

	struct cb_free_inode_ctx
	{
		cb_dsio_t cb;
		unsigned long node_id;
	};

	struct cb_block_allocation_ctx
	{
		cb_dsio_t cb;
		inode_t* node;
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

	void write_block_allocator(allocator_t&, cb_dsio_t, request_t*);
	void write_inode_allocator(allocator_t&, cb_dsio_t, request_t*);
	void write_inode(unsigned long node_id, const inode_t&, cb_dsio_t, request_t*);

	/* These two operations increment the finished_req counter by 3 */
	void allocate_inode(unsigned long& node_id, cb_err_t, request_t*);
	void free_inode(unsigned long node_id, cb_dsio_t, request_t*);

	static void cb_allocator(size_t handle, int res, void* arg);
	static void cb_read_inode(size_t handle, int read, void* arg);
	static void cb_write_inode(size_t handle, int read, void* arg);

	void cb_allocate_inode(cb_allocate_inode_ctx c, request_t* req);
	void cb_allocate_inode2(cb_allocate_inode_ctx c, request_t* req);
	void cb_free_inode(cb_free_inode_ctx c, request_t* req);
	void cb_free_inode2(cb_free_inode_ctx c, request_t* req);

	/* Increments the finished_req counter by 3 */
	void free_blocks_of_file(inode_t& node, cb_dsio_t, request_t*);

	void cb_free_blocks_of_file(cb_block_allocation_ctx c, request_t* req);
	void cb_free_blocks_of_file2(cb_block_allocation_ctx c, request_t* req);


	/* Callbacks for fs operations */
	void cb_getfsattr(request_t* req);
	void cb_lookup(request_t* req);
	void cb_lookup2(request_t* req);
	void cb_getattr(request_t* req);
	void cb_readdir(request_t* req);

	void cb_mkdir(request_t* req);
	void cb_mkdir2(int res, request_t* req);
	void cb_mkdir3(request_t* req);
	void cb_mkdir4(request_t* req);

	void cb_rmdir(request_t* req);
	void cb_rmdir2(request_t* req);
	void cb_rmdir3(request_t* req);

	void cb_create(request_t*);
	void cb_create2(int res, request_t* req);
	void cb_create3(request_t* req);
	void cb_create4(request_t* req);

	void cb_unlink(request_t*);
	void cb_unlink2(request_t*);
	void cb_unlink3(request_t*);

	void cb_free_inode_explicit(request_t* req);
	void cb_free_inode_explicit2(request_t* req);

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

	sdfs::async_handle_t mkdir(unsigned long parent, const char* name, struct stat& dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	/* If auto_free_inode is false, the child inode will not be deleted. This
	 * might be usedful to implement the 'keep open files until closed'
	 * semantics.  These inodes can be deleted later using free_inode_explicit()
	 * - however beware that it does (currently) not check if the inode is not
	 * linked anywhere...
	 *
	 * @param ino may be null
	 * */
	sdfs::async_handle_t rmdir(unsigned long parent, const char* name,
			bool auto_free_inode, unsigned long *ino,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t create(unsigned long parent, const char* name, struct stat& dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t unlink(unsigned long parent, const char* name,
			bool auto_free_inode, unsigned long* ino,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	sdfs::async_handle_t read();
	sdfs::async_handle_t write();

	sdfs::async_handle_t free_inode_explicit(unsigned long ino,
			sdfs::cb_async_finished_t cb_finished, void* arg);
};

#endif /* __SDFS_FS_INTERNAL_H */
