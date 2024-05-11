#ifndef __CTRL_CTX_H
#define __CTRL_CTX_H

#include <list>
#include <map>
#include <optional>
#include <queue>
#include <deque>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <variant>
#include "common/fixed_buffer.h"
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"
#include "common/prot_dd.h"
#include "common/open_list.h"
#include "common/io_uring.h"
#include "common/timerfd.h"

extern "C" {
#include <netinet/in.h>
}


static_assert(sizeof(unsigned long) >= 8);
static_assert(sizeof(long) >= 8);

/* Prototypes */
class ctrl_dd;
class ctrl_mp_client;
class ctrl_client;


template<class T>
class lock_witness final
{
public:
	using unlock_fn_t = std::function<void(T&)>;

protected:
	unlock_fn_t f;
	T t;
	bool locked;

public:
	lock_witness()
		: locked(false)
	{
	}

	lock_witness(unlock_fn_t f, T t)
		: f(f), t(t), locked(true)
	{
	}

	lock_witness(lock_witness&& o)
		: f(o.f), t(std::move(o.t)), locked(o.locked)
	{
		o.locked = false;
	}

	lock_witness& operator=(lock_witness&& o)
	{
		if (locked)
			f(t);

		f = o.f;
		t = std::move(o.t);
		locked = o.locked;

		o.locked = false;
		return *this;
	}

	~lock_witness()
	{
		if (locked)
			f(t);
	}
};


/* Defines the placement of data blocks and metadata on the dds */
struct data_map_t
{
	/* Data */
	/* 1 MiB */
	const size_t block_size = 1024 * 1024;

	/* Data placement order */
	unsigned n_dd;
	std::vector<ctrl_dd*> dd_rr_order;

	/* n_dd * block_size */
	size_t stripe_size;
	size_t total_data_size;

	/* Inode directory; replicated on all dds */
	size_t inode_directory_size;
	size_t total_inode_count;

	/* Data allocation bitmap */
	const size_t allocation_granularity = 1024 * 1024;
	size_t allocation_bitmap_size = 0;
};

/* Cached inode */
struct inode
{
	/* After modification which has not been written to disk yet */
	bool dirty = false;

	/* Actual inode data */
	enum inode_type : unsigned
	{
		TYPE_FREE = 0,
		TYPE_FILE = 1,
		TYPE_DIRECTORY = 2,
		TYPE_EXTENSION = 3
	} type = TYPE_FREE;

	size_t nlink = 0;
	size_t size = 0;

	/* In microseconds */
	unsigned long mtime{};


	/* For files */
	struct allocation {
		size_t offset;
		size_t size;

		inline allocation()
		{
		}

		inline allocation(size_t offset, size_t size)
			: offset(offset), size(size)
		{
		}
	};
	std::vector<allocation> allocations;

	size_t get_allocated_size() const;


	/* For directories (name, inode, type) */
	std::vector<std::tuple<std::string, unsigned long, unsigned>> files;

	bool enough_space_for_file(const std::string& name) const;


	/* The buffer needs to be 4096 bytes long */
	void serialize(char* buf) const;
	void parse(const char* buf);


	/* References by clients ('open files') */
	std::vector<std::weak_ptr<ctrl_mp_client>> client_refs;
};


struct inode_lock_request_t
{
	using cb_acquired_t = std::function<void(inode_lock_request_t&)>;

	unsigned long node_id = 0;
	bool write = false;
	cb_acquired_t cb_acquired;
};
typedef lock_witness<inode_lock_request_t> inode_lock_witness;

struct inode_allocator_lock_request_t
{
	using cb_acquired_t = std::function<void(inode_allocator_lock_request_t&)>;

	cb_acquired_t cb_acquired;
};
typedef lock_witness<inode_allocator_lock_request_t> inode_allocator_lock_witness;

struct block_allocator_lock_request_t
{
	using cb_acquired_t = std::function<void(block_allocator_lock_request_t&)>;

	cb_acquired_t cb_acquired;
};
typedef lock_witness<block_allocator_lock_request_t> block_allocator_lock_witness;


struct get_inode_request_t final
{
	using cb_finished_t = std::function<void(get_inode_request_t&&)>;

	get_inode_request_t() = default;
	get_inode_request_t(get_inode_request_t&&) = default;
	get_inode_request_t& operator=(get_inode_request_t&&) = default;

	/* Input */
	unsigned long node_id = 0;
	cb_finished_t cb_finished;

	/* Will be filled by get_inode */
	int result = -1;
	std::shared_ptr<inode> node;
	bool was_in_cache = false;

	/* Data for use by caller of get_inode */
	std::vector<inode_lock_witness> ilocks;
	inode_allocator_lock_witness ialloc_lock;
};


struct inode_directory_t
{
	/* Inode locks */
	struct node_lock_t {
		/* Negative means write lock, positive number of current read locker */
		long lockers = 0;
		std::list<inode_lock_request_t> reqs;
	};
	std::map<unsigned long, node_lock_t> node_locks;

	/* Cached inodes */
	std::map<unsigned long, std::shared_ptr<inode>> cached_inodes;


	/* Inode allocator lock */
	bool allocator_locked = false;
	std::list<inode_allocator_lock_request_t> allocator_lock_reqs;

	/* Inode allocator
	 * Note that inode numbers start at 1, but the inode with id 1 is encoded in
	 * the first bit of the bitmap. So the bit-position is node_id - 1.
	 * Accordingly same holds for the on-disk storage of inodes. */
	fixed_aligned_buffer _allocator_buffer;
	uint8_t* allocator_bitmap = nullptr;

	/* true if the cached inode allocator differs from the version stored on dd
	 * */
	bool allocator_dirty = false;

	size_t allocated_count = 0;
};

struct block_allocator_t
{
	/* Block allocator lock */
	bool locked = false;
	std::list<block_allocator_lock_request_t> lock_reqs;

	/* Allocation bitmap */
	fixed_aligned_buffer _buffer;
	uint8_t* bitmap = nullptr;

	/* true if the cached bitmap differs from the version stored on dd */
	bool dirty = false;

	size_t allocated_count = 0;
};


/* Contexts for dd IO */
struct dd_read_request_t
{
	using cb_completed_t = std::function<void(dd_read_request_t&&)>;

	ctrl_dd* dd;
	size_t offset;
	size_t size;
	cb_completed_t cb_completed;

	/* Will be filled by dd_read */
	int result = -1;
	const char* data = nullptr;

	/* The data is stored somewhere in this buffer */
	dynamic_aligned_buffer _buf;
};

struct dd_write_request_t
{
	using cb_completed_t = std::function<void(dd_write_request_t&&)>;

	ctrl_dd* dd;
	size_t offset;
	size_t size;
	const char* data = nullptr;
	cb_completed_t cb_completed;

	/* Will be filled by dd_write */
	int result = -1;
};


/* Contexts for client requests */
struct ctx_c_r_create
{
	std::shared_ptr<ctrl_client> client;
	prot::client::req::create msg;

	unsigned long node_id;
	std::shared_ptr<inode> node;
	std::shared_ptr<inode> parent_node;

	inode_allocator_lock_witness ialloc_lck;
	inode_lock_witness n_ilck;
	inode_lock_witness p_ilck;

	/* msg cannot be copy-assigned; and move-assignment difficult because of
	 * unique_ptr-to-parent-class source */
	inline ctx_c_r_create(const prot::client::req::create& msg)
		: msg(msg)
	{
	}
};

struct ctx_c_r_unlink
{
	std::shared_ptr<ctrl_client> client;
	prot::client::req::unlink msg;

	inode_lock_witness p_ilck;
	inode_lock_witness e_ilck;
	std::shared_ptr<inode> parent_node;

	unsigned long entry_node_id{};

	inline ctx_c_r_unlink(const prot::client::req::unlink& msg)
		: msg(msg)
	{
	}
};

struct ctx_c_r_forget
{
	std::shared_ptr<ctrl_client> client;
	prot::client::req::forget msg;

	/* Keep the lock on the block allocator longest (basic idea: In case of
	 * unclean shutdown, inodes should not reference unallocated block ranges.
	 * However to guarantee this, a lot more effort woudl be requried.) */
	block_allocator_lock_witness blck;

	inode_allocator_lock_witness ialck;
	inode_lock_witness ilck;

	std::shared_ptr<inode> node;

	inline ctx_c_r_forget(const prot::client::req::forget& msg)
		: msg(msg)
	{
	}
};

struct ctx_c_r_read
{
	std::shared_ptr<ctrl_client> client;
	prot::client::req::read msg;

	unsigned long long t_start;

	inode_lock_witness ilck;
	std::shared_ptr<inode> node;

	size_t read_size_total{};
	size_t reply_header_size;
	dynamic_aligned_buffer buf;

	struct block_t
	{
		size_t offset;
		size_t size;

		ctrl_dd* dd;
		size_t dd_offset;

		bool completed = false;
		int result = -1;

		inline block_t(size_t offset, size_t size, ctrl_dd* dd, size_t dd_offset)
			: offset(offset), size(size), dd(dd), dd_offset(dd_offset)
		{
		}
	};
	std::vector<block_t> blocks;

	inline ctx_c_r_read(const prot::client::req::read& msg)
		: msg(msg)
	{
	}
};

struct ctx_c_r_write
{
	std::shared_ptr<ctrl_client> client;
	prot::client::req::write msg;
	dynamic_buffer _buf;

	unsigned long long t_start;

	inode_lock_witness ilck;
	std::shared_ptr<inode> node;

	size_t allocated_size{};

	struct block_t
	{
		size_t offset;
		size_t size;

		ctrl_dd* dd;
		size_t dd_offset;

		bool completed = false;
		int result = -1;

		inline block_t(size_t offset, size_t size, ctrl_dd* dd, size_t dd_offset)
			: offset(offset), size(size), dd(dd), dd_offset(dd_offset)
		{
		}
	};
	std::vector<block_t> blocks;

	inline ctx_c_r_write(const prot::client::req::write& msg)
		: msg(msg)
	{
	}
};

struct ctx_m_s_balloc
{
	block_allocator_lock_witness blck;

	struct block_t
	{
		size_t offset;
		size_t size;
		const char* data;

		ctrl_dd* dd;

		bool completed = false;
		int result = -1;

		inline block_t(size_t offset, size_t size, const char* data, ctrl_dd* dd)
			: offset(offset), size(size), data(data), dd(dd)
		{
		}
	};
	std::vector<block_t> blocks;
};

struct ctx_m_s_ialloc
{
	inode_allocator_lock_witness ialck;

	struct block_t
	{
		size_t offset;
		size_t size;
		const char* data;

		ctrl_dd* dd;

		bool completed = false;
		int result = -1;

		inline block_t(size_t offset, size_t size, const char* data, ctrl_dd* dd)
			: offset(offset), size(size), data(data), dd(dd)
		{
		}
	};
	std::vector<block_t> blocks;
};

struct ctx_m_s_inodes
{
	inode_lock_witness ilck;

	fixed_buffer buf{4096};

	struct node_to_store_t
	{
		unsigned long node_id;
		std::shared_ptr<inode> node;

		node_to_store_t(unsigned long node_id, std::shared_ptr<inode> node)
			: node_id(node_id), node(node)
		{
		}
	};
	std::vector<node_to_store_t> nodes_to_store;

	struct block_t
	{
		ctrl_dd* dd;

		bool completed = false;
		int result = -1;

		inline block_t(ctrl_dd* dd)
			: dd(dd)
		{
		}
	};
	std::vector<block_t> blocks;
};


struct ctx_m_g_inode
{
	get_inode_request_t req;

	inline ctx_m_g_inode(get_inode_request_t&& req)
		: req(std::move(req))
	{
	}
};


struct ctx_m_purge_inodes
{
	std::vector<unsigned long> to_examine;

	unsigned long node_id{};

	inode_allocator_lock_witness ialck;
	inode_lock_witness ilck;
	block_allocator_lock_witness blck;

	std::shared_ptr<inode> node;
};


struct ctrl_queued_msg final
{
	std::variant<dynamic_buffer, dynamic_aligned_buffer> vbuf;
	const size_t msg_len;

	inline ctrl_queued_msg(
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& vbuf,
			size_t msg_len)
		: vbuf(std::move(vbuf)), msg_len(msg_len)
	{
	}

	inline const char* buf_ptr()
	{
		if (std::holds_alternative<dynamic_buffer>(vbuf))
			return std::get<dynamic_buffer>(vbuf).ptr();
		else
			return std::get<dynamic_aligned_buffer>(vbuf).ptr();
	}

	inline void return_buffer(dynamic_aligned_buffer_pool& pool)
	{
		if (std::holds_alternative<dynamic_aligned_buffer>(vbuf))
			pool.return_buffer(std::move(std::get<dynamic_aligned_buffer>(vbuf)));
	}
};


struct ctrl_dd final
{
	WrappedFD wfd;

	unsigned id;
	char gid[16];
	int port;

	size_t size;

	/* Only true after the DD's connection has been fully initialized */
	bool connected = false;


	/* Receiving messages from the dd */
	dynamic_aligned_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Sending messages to the dd */
	std::queue<ctrl_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	/* Outstanding requests */
	std::map<uint64_t, dd_read_request_t> read_reqs;
	std::map<uint64_t, dd_write_request_t> write_reqs;


	/* Metadata offsets */
	size_t allocation_bitmap_offset = 0;
	size_t inode_directory_offset = 0;
	size_t inode_bitmap_offset = 0;

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


/* For multipathing */
struct ctrl_mp_client
{
	/* 0 means invalid */
	const uint64_t id;

	ctrl_mp_client(uint64_t id)
		: id(id)
	{
	}
};


struct ctrl_client final
{
	/* After a client was removed from the list but is still kept alive through
	 * a shared_ptr */
	bool invalid = false;

	WrappedFD wfd;

	/* Multipathing */
	std::shared_ptr<ctrl_mp_client> mp_client;

	/* Receive messages */
	dynamic_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Send messages */
	std::deque<ctrl_queued_msg> send_queue;
	size_t send_msg_pos = 0;
	struct iovec send_iovs[128]{};

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


class ctrl_ctx final
{
protected:
	FileConfig cfg;
	bool format_on_startup = false;

	bool quit_requested = false;
	bool quit_main_loop = false;

	bool background_job_enabled = false;

	Epoll epoll;
	SignalFD sfd{
		{SIGINT, SIGTERM},
		epoll,
		std::bind_front(&ctrl_ctx::on_signal, this)};

	TimerFD bg_tfd{
		epoll,
		std::bind_front(&ctrl_ctx::on_background_timer, this)};

	/* NOTE: Epoll comes before because IOUring polls epoll's filedescriptor */
	const unsigned io_uring_max_req_in_flight = 4080;
	/* poll + in-flight */
	IOUring io_uring{next_power_of_two(io_uring_max_req_in_flight + 2)};

	unsigned io_uring_req_in_flight = 0;

	/* dds */
	std::list<ctrl_dd> dds;

	/* clients */
	WrappedFD client_lfd;
	std::vector<std::shared_ptr<ctrl_client>> clients;
	std::vector<std::weak_ptr<ctrl_mp_client>> mp_clients;

	/* data map */
	data_map_t data_map;

	/* inode directory */
	inode_directory_t inode_directory;

	/* Block allocator */
	block_allocator_t block_allocator;

	/* Request id generator */
	uint64_t next_request_id = 0;
	uint64_t get_request_id();

	/* Buffer pools for requests and dd IO (two different pools because the
	 * request classes can differ in size) */
	dynamic_aligned_buffer_pool buf_pool_req{4096, 8};
	dynamic_aligned_buffer_pool buf_pool_dd_io{4096, 64};


	/* Statistics */
	size_t client_req_cnt_read = 0;
	size_t client_req_cnt_write = 0;

	/* Global state control */
	bool stop_accepting_new_clients = false;
	bool stop_accepting_client_requests = false;


	/* Internal operations */
	/* Locks */
	void lock_inode(inode_lock_request_t&);
	void unlock_inode(inode_lock_request_t&);

	void lock_inode_allocator(inode_allocator_lock_request_t&);
	void unlock_inode_allocator(inode_allocator_lock_request_t&);

	void lock_block_allocator(block_allocator_lock_request_t&);
	void unlock_block_allocator(block_allocator_lock_request_t&);

	/* Blocks */
	/* get_free_blocks returns -1 if not that many consecutive blocks are
	 * available, or the index to the region.
	 * Both functions Must be called with a lock on the block allocator. */
	ssize_t get_free_blocks(size_t count);
	void unallocate_blocks(size_t start, size_t count);

	/* Inodes */
	/* Must be called with a lock (read or write) on the inode */
	void get_inode(get_inode_request_t&&);

	/* Callback internally used by get_inode */
	void cb_m_g_inode(std::shared_ptr<ctx_m_g_inode> rctx, dd_read_request_t&& dd_req);

	/* Inode directory */
	void mark_inode_allocated(unsigned long);
	void mark_inode_unallocated(unsigned long);

	/* Returns < 0 if no free inode is available */
	long get_free_inode();

	void inode_add_client_ref(std::shared_ptr<inode> node, std::shared_ptr<ctrl_client> client);
	void inode_remove_client_ref(std::shared_ptr<inode> node, std::shared_ptr<ctrl_client> client);

	void delete_inode(unsigned long node_id, std::shared_ptr<inode> node);


	/* Returns [(offset, size, file_offset)] */
	std::vector<std::tuple<size_t, size_t, size_t>> map_file_region(
			const inode& node, size_t offset, size_t size);


	/* dd IO interface */
	void dd_read(dd_read_request_t&& req);
	void dd_write(dd_write_request_t&& req);

	/* Only to be used during initialization, before the main loop is running */
	fixed_buffer dd_read_sync_startup(ctrl_dd* dd, size_t offset, size_t size);


	/* Be careful when calling these functions */
	void remove_client(decltype(clients)::iterator i);
	void remove_client(std::shared_ptr<ctrl_client> client);

	/* Client-size multipathing */
	std::shared_ptr<ctrl_mp_client> create_mp_client();
	std::shared_ptr<ctrl_mp_client> find_mp_client(uint64_t id);

	void print_cfg();

	std::pair<WrappedFD, struct sockaddr_in6> initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_client_listener();

	void build_data_map();
	void initialize_block_allocator();
	void initialize_inode_directory();
	void initialize_root_directory();

	void on_signal(int s);
	void on_background_timer();

	void on_epoll_ready(int res);

	void on_client_lfd(int fd, uint32_t events);

	void on_dd_fd(ctrl_dd* dd, int fd, uint32_t events);
	void on_client_fd(std::shared_ptr<ctrl_client> client, int fd, uint32_t events);
	void on_client_writev_finished(std::shared_ptr<ctrl_client> client, int res);


	bool process_dd_message(ctrl_dd& dd, dynamic_aligned_buffer&& buf, size_t msg_len);
	bool process_dd_message(ctrl_dd& dd, prot::dd::reply::read& msg, dynamic_aligned_buffer&& buf);
	bool process_dd_message(ctrl_dd& dd, prot::dd::reply::write& msg);

	bool send_message_to_dd(ctrl_dd& dd, const prot::msg& msg,
			const char* data = nullptr, size_t data_length = 0);

	bool send_message_to_dd(ctrl_dd& dd,
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len);


	bool process_client_message(std::shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::connect& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::getattr& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::getfattr& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::readdir& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::create& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::unlink& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::forget& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::read& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::write& msg,
			dynamic_buffer&& buf);

	bool send_message_to_client(std::shared_ptr<ctrl_client> client, const prot::msg& msg);
	bool send_message_to_client(std::shared_ptr<ctrl_client> client,
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len);


	/* Callbacks for client request processing */
	void cb_c_r_getfattr_ilock(std::shared_ptr<ctrl_client>, req_id_t, inode_lock_request_t&);
	void cb_c_r_getfattr_inode(std::shared_ptr<ctrl_client>, req_id_t, get_inode_request_t&&);

	void cb_c_r_readdir_ilock(std::shared_ptr<ctrl_client> client, req_id_t req_id,
			inode_lock_request_t& lck_req);
	void cb_c_r_readdir_inode(std::shared_ptr<ctrl_client> client, req_id_t req_id,
			get_inode_request_t&& req);

	void cb_c_r_create_iallock(std::shared_ptr<ctx_c_r_create>, inode_allocator_lock_request_t&);
	void cb_c_r_create_ilock(std::shared_ptr<ctx_c_r_create>, inode_lock_request_t&);
	void cb_c_r_create_ilockp(std::shared_ptr<ctx_c_r_create>, inode_lock_request_t&);
	void cb_c_r_create_ialloc(std::shared_ptr<ctx_c_r_create>, inode_allocator_lock_request_t&);
	void cb_c_r_create_getp(std::shared_ptr<ctx_c_r_create>, get_inode_request_t&&);

	void cb_c_r_unlink_ilock(std::shared_ptr<ctx_c_r_unlink> rctx, inode_lock_request_t& ilck);
	void cb_c_r_unlink_getnode(std::shared_ptr<ctx_c_r_unlink> rctx, get_inode_request_t&& ireq);
	void cb_c_r_unlink_lock_entry(std::shared_ptr<ctx_c_r_unlink> rctx, inode_lock_request_t& ilck);
	void cb_c_r_unlink_get_entry(std::shared_ptr<ctx_c_r_unlink> rctx, get_inode_request_t&& req);

	void cb_c_r_forget_ialck(std::shared_ptr<ctx_c_r_forget> rctx, inode_allocator_lock_request_t& ialck);
	void cb_c_r_forget_ilck(std::shared_ptr<ctx_c_r_forget> rctx, inode_lock_request_t& ilck);
	void cb_c_r_forget_getnode(std::shared_ptr<ctx_c_r_forget> rctx, get_inode_request_t&& node_req);
	void cb_c_r_forget_blck(std::shared_ptr<ctx_c_r_forget> rctx, block_allocator_lock_request_t blck);

	void cb_c_r_read_ilock(std::shared_ptr<ctx_c_r_read> rctx, inode_lock_request_t& ilck);
	void cb_c_r_read_getnode(std::shared_ptr<ctx_c_r_read> rctx, get_inode_request_t&& ireq);
	void cb_c_r_read_dd(std::shared_ptr<ctx_c_r_read> rctx, size_t bi, dd_read_request_t&& req);

	void cb_c_r_write_ilock(std::shared_ptr<ctx_c_r_write> rctx, inode_lock_request_t& ilck);
	void cb_c_r_write_getnode(std::shared_ptr<ctx_c_r_write> rctx, get_inode_request_t&& ireq);
	void cb_c_r_write_balloc(std::shared_ptr<ctx_c_r_write> rctx, block_allocator_lock_request_t& blck);
	void cb_c_r_write_write(std::shared_ptr<ctx_c_r_write> rctx);
	void cb_c_r_write_dd(std::shared_ptr<ctx_c_r_write> rctx, size_t bi, dd_write_request_t&& req);

	/* Storing metadata on disk */
	void store_metadata();

	void store_allocation_bitmap();
	void store_inode_allocator_bitmap();
	void store_inodes();

	/* Callbacks and internal functions for metadata writing */
	void cb_m_s_balloc_lck(std::shared_ptr<ctx_m_s_balloc> rctx, block_allocator_lock_request_t& blck);
	void cb_m_s_balloc_dd(std::shared_ptr<ctx_m_s_balloc> rctx, size_t bi, dd_write_request_t&& req);

	void cb_m_s_ialloc_lck(std::shared_ptr<ctx_m_s_ialloc> rctx, inode_allocator_lock_request_t& blck);
	void cb_m_s_ialloc_dd(std::shared_ptr<ctx_m_s_ialloc> rctx, size_t bi, dd_write_request_t&& req);

	void store_inodes_node(std::shared_ptr<ctx_m_s_inodes> rctx);
	void cb_m_s_inodes_ilock(std::shared_ptr<ctx_m_s_inodes> rctx, inode_lock_request_t& ilck);
	void cb_m_s_inodes_dd(std::shared_ptr<ctx_m_s_inodes> rctx, size_t bi, dd_write_request_t&& req);


	/* Deleting unreferenced inodes */
	/* This is usually done in response to a FORGET request of a client. However
	 * sometimes clients do not send forget requests - hence scan periodically
	 * for unreferenced inodes and delete them. */
	std::weak_ptr<ctx_m_purge_inodes> purge_unreferenced_inodes_witness;
	bool purge_unreferenced_inodes_all_scanned = false;

	void purge_unreferenced_inodes();
	void purge_inodes_next(std::shared_ptr<ctx_m_purge_inodes> rctx);
	void cb_m_purge_inodes_ialck(std::shared_ptr<ctx_m_purge_inodes> rctx, inode_allocator_lock_request_t& ialck);
	void cb_m_purge_inodes_ilck(std::shared_ptr<ctx_m_purge_inodes> rctx, inode_lock_request_t& ilck);
	void cb_m_purge_inodes_getnode(std::shared_ptr<ctx_m_purge_inodes> rctx, get_inode_request_t&& node_req);
	void cb_m_purge_inodes_blck(std::shared_ptr<ctx_m_purge_inodes> rctx, block_allocator_lock_request_t blck);


	/* Shutdown procedure */
	int shutdown_state = 0;

	/* To be called in every main loop iteration once shutdown is to be
	 * initiated. */
	void perform_shutdown();

	void initiate_shutdown();
	void shutdown_wait_for_operations();
	void shutdown_wait_metadata();


public:
	ctrl_ctx();
	~ctrl_ctx();

	/* If format is true, the filesystem will be wiped during startung (useful
	 * for initializing new filesystems) */
	void initialize(bool format);

	void main();
};

#endif /* __CTRL_CTX_H */
