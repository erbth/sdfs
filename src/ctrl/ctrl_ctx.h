#ifndef __CTRL_CTX_H
#define __CTRL_CTX_H

#include <string>
#include <optional>
#include <list>
#include <vector>
#include <map>
#include <queue>
#include <utility>
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"
#include "common/prot_ctrl.h"

extern "C" {
#include <netinet/in.h>
}


static_assert(sizeof(unsigned long) >= 8);
static_assert(sizeof(long) >= 8);


/* Used when callbacks need a lock witness to be present while being called,
 * e.g. when handling requests */
template<class W, typename _Signature>
class req_cb_def;

template<class W, class R, class... Args>
class req_cb_def<W, R(Args...)> final
{
protected:
	W w;

	using F = std::function<R(Args...)>;
	F fn;

public:
	req_cb_def(W&& w, F fn)
		: w(std::move(w)), fn(fn)
	{
	}

	R operator()(Args... args)
	{
		return fn(args...);
	}

	void assert_lock()
	{
		if (!w.lock_held())
			throw std::runtime_error("lock not held");
	}
};

/* Same as above but with more general payload */
template <class P, typename _Signature>
class cb_def_p;

template<class P, class R, class... Args>
class cb_def_p<P, R(P&&, Args...)> final
{
protected:
	P payload;

	using F = std::function<R(P&&, Args...)>;
	F fn;

public:
	cb_def_p(P&& payload, F fn)
		: payload(std::move(payload)), fn(fn)
	{
	}

	R operator()(Args... args)
	{
		return fn(std::move(payload), args...);
	}
};


/* Locks */
class ctrl_ctx;

class inode_lock_witness final
{
protected:
	ctrl_ctx* ctrl;
	unsigned long node_id;

	void clean();

public:
	inode_lock_witness();
	inode_lock_witness(ctrl_ctx& ctrl, unsigned long node_id);

	inode_lock_witness(inode_lock_witness&&);
	inode_lock_witness& operator=(inode_lock_witness&&);

	~inode_lock_witness();

	bool lock_held() const;
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
		/* TYPE_EXTENSION_FILE = 3, */
		/* TYPE_EXTENSION_DIRECTORY = 4 */
	} type = TYPE_FREE;

	std::string name;

	size_t nlink = 0;
	size_t size = 0;

	/* In microseconds */
	unsigned long mtime;

	/* For files */
	struct allocation {
		size_t offset;
		size_t size;
	};
	std::vector<allocation> allocations;

	/* For directories */
	std::vector<unsigned long> files;


	size_t get_allocated_size() const;

	/* The buffer needs to be 4096 bytes long */
	void serialize(char* buf) const;
	void parse(const char* buf);
};

struct inode_directory_t
{
	/* Inode locks (negative means write lock) */
	std::map<unsigned long, long> node_locks;

	/* Cached inodes */
	std::map<unsigned long, std::shared_ptr<inode>> cached_inodes;
};

/* File/directory information */
struct dir_entry
{
	unsigned long node_id = 0;

	enum dir_entry_type : unsigned {
		TYPE_INVALID = 0,
		TYPE_FILE = 1,
		TYPE_DIRECTORY = 2
	} type = TYPE_INVALID;

	std::string name;

	inline dir_entry()
	{
	}

	inline dir_entry(unsigned long node_id, dir_entry_type type, const std::string& name)
		: node_id(node_id), type(type), name(name)
	{
	}
};


/* Request queue structures */
struct request_t
{
	const uint64_t req_id;

	inline request_t(uint64_t req_id)
		: req_id(req_id)
	{
	}
};

struct inode_lock_request_t : public request_t
{
	unsigned long node_id;

	inline inode_lock_request_t(uint64_t req_id, unsigned long node_id)
		: request_t(req_id), node_id(node_id)
	{
	}
};


struct ctrl_queued_msg
{
	dynamic_buffer buf;
	const size_t msg_len;

	inline ctrl_queued_msg(dynamic_buffer&& buf, size_t msg_len)
		: buf(std::move(buf)), msg_len(msg_len)
	{
	}
};

struct ctrl_dd final
{
	WrappedFD wfd;

	unsigned id;
	char gid[16];
	int port;

	size_t size;
	size_t usable_size;

	bool connected = false;

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};

struct ctrl_ctrl final
{
	WrappedFD wfd;

	unsigned id;
	std::string addr_str;

	/* Reveive messages */
	dynamic_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Send messages */
	std::queue<ctrl_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


struct data_map_t
{
	/* 1 MiB */
	const size_t block_size = 1024 * 1024;

	unsigned n_dd;
	std::vector<ctrl_dd*> dd_rr_order;

	/* n_dd * block_size */
	size_t stripe_size;

	size_t total_size;
	size_t total_inodes;
};


struct ctrl_client final
{
	/* After a client was removed from the list but is still kept alive through
	 * a shared_ptr */
	bool invalid = false;

	WrappedFD wfd;

	/* Receive messages */
	dynamic_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Send messages */
	std::queue<ctrl_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	/* IO requests */

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};

class ctrl_ctx final
{
protected:
	const unsigned id;
	const std::optional<const std::string> bind_addr_str;

	FileConfig cfg;
	unsigned min_ctrl_id = 0;

	bool quit_requested = false;

	Epoll epoll;
	SignalFD sfd{
		{SIGINT, SIGTERM},
		epoll,
		std::bind_front(&ctrl_ctx::on_signal, this)};

	WrappedFD sync_lfd;
	WrappedFD client_lfd;

	/* dds */
	std::list<ctrl_dd> dds;

	/* Other controllers */
	std::list<ctrl_ctrl> ctrls;
	std::list<WrappedFD> new_ctrl_conns;

	/* clients */
	std::vector<std::shared_ptr<ctrl_client>> clients;

	/* data map */
	data_map_t data_map;

	/* Request id generator */
	uint64_t next_request_id = 0;
	uint64_t get_request_id();


	/* TODO: add witness objects */
	using cb_lock_data_range_t = std::function<void(int result)>;

	void lock_data_range(size_t offset, size_t length, bool write, cb_lock_data_range_t cb);

	/* inode directory */
	inode_directory_t inode_directory;

	/* TODO: add witness objects */
	using cb_lock_inode_directory_t = std::function<void(int result)>;
	using cb_lock_inode_t = std::function<void(int result, inode_lock_witness&&)>;

	using cb_get_inode_t = req_cb_def<inode_lock_witness, void(int result, std::shared_ptr<inode>)>;
	using cb_write_inode_t = std::function<void(int result)>;
	using cb_get_unused_inode_t = std::function<void(int result, unsigned long inode_id)>;

	using cb_listdir_t = std::function<void(int result, std::vector<dir_entry>&&)>;
	using cb_unlink_t = std::function<void(int result)>;
	using cb_add_link_t = std::function<void(int result)>;

	void lock_inode_directory(cb_lock_inode_directory_t cb);
	void lock_inode(unsigned long id, cb_lock_inode_t cb);

	void get_inode(unsigned long node_id, cb_get_inode_t&& cb);
	void write_inode(inode* n, cb_write_inode_t cb);
	void get_unused_inode(cb_get_unused_inode_t cb);

	/* fs (file/directory handling) */
	void listdir(unsigned long node_id, cb_listdir_t cb);
	void unlink(unsigned long parent_inode_id, unsigned long inode_id, cb_unlink_t cb);
	void add_link(unsigned long parent_inode_id, unsigned long inode_id, cb_add_link_t cb);


	/* Synchronization with other controllers */
	using cb_fetch_inode_from_ctrls_t = cb_def_p<cb_get_inode_t,
		  void(cb_get_inode_t&&, std::shared_ptr<inode>)>;

	struct inode_request_t : public request_t
	{
		unsigned long node_id;

		/* The passed inode is not in the inode directory */
		cb_fetch_inode_from_ctrls_t cb;

		inline inode_request_t(uint64_t req_id, unsigned long node_id, cb_fetch_inode_from_ctrls_t&& cb)
			: request_t(req_id), node_id(node_id), cb(std::move(cb))
		{
		}
	};

	std::map<uint64_t, inode_lock_request_t> inode_lock_requests;
	std::map<uint64_t, inode_request_t> inode_requests;

	void fetch_inode_from_ctrls(unsigned long node_id, cb_fetch_inode_from_ctrls_t&& cb);


	/* Be careful when calling these functions */
	void remove_client(decltype(clients)::iterator i);
	void remove_client(std::shared_ptr<ctrl_client> client);

	void close_ctrl_conn(ctrl_ctrl* ctrl);

	void print_cfg();

	void initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_sync_listener();
	void initialize_client_listener();
	void initialize_connect_ctrls();

	void build_data_map();
	void initialize_inode_directory();
	void initialize_root_directory();

	void on_signal(int s);

	void on_sync_lfd(int fd, uint32_t events);
	void on_client_lfd(int fd, uint32_t events);

	void on_dd_fd(int fd, uint32_t events);
	void on_client_fd(std::shared_ptr<ctrl_client> client, int fd, uint32_t events);
	void on_new_ctrl_conn_fd(int fd, uint32_t events);
	void on_ctrl_fd(ctrl_ctrl* ctrl, int fd, uint32_t events);


	bool process_client_message(std::shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::getattr& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::getfattr& msg);
	bool process_client_message(std::shared_ptr<ctrl_client> client, prot::client::req::readdir& msg);

	bool send_message_to_client(std::shared_ptr<ctrl_client> client, const prot::msg& msg);
	bool send_message_to_client(std::shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len);


	bool process_ctrl_message(ctrl_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len);
	bool process_ctrl_message(ctrl_ctrl* ctrl, prot::ctrl::req::ctrlinfo& msg);
	bool process_ctrl_message(ctrl_ctrl* ctrl, prot::ctrl::req::fetch_inode& msg);
	bool process_ctrl_message(ctrl_ctrl* ctrl, prot::ctrl::reply::fetch_inode& msg);

	bool send_message_to_ctrl(ctrl_ctrl* ctrl, const prot::msg& msg);
	bool send_message_to_ctrl(ctrl_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len);


	/* Lock witnesses are friends */
	friend inode_lock_witness;

public:
	ctrl_ctx(unsigned id, const std::optional<const std::string>& bind_addr);
	~ctrl_ctx();

	void initialize();

	void main();
};

#endif /* __CTRL_CTX_H */
