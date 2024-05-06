#ifndef __COM_CTX_H
#define __COM_CTX_H

#include <atomic>
#include <list>
#include <queue>
#include <map>
#include <functional>
#include <mutex>
#include <thread>
#include "common/utils.h"
#include "common/file_config.h"
#include "common/epoll.h"
#include "common/eventfd.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"

struct queued_msg
{
	dynamic_buffer buf;
	const size_t msg_len;

	inline queued_msg(dynamic_buffer&& buf, size_t msg_len)
		: buf(std::move(buf)), msg_len(msg_len)
	{
	}
};


struct req_getattr_result
{
	size_t size_total;
	size_t size_used;

	size_t inodes_total;
	size_t inodes_used;
};

typedef std::function<void(req_getattr_result)> req_cb_getattr_t;
typedef std::function<void(prot::client::reply::getfattr&)> req_cb_getfattr_t;
typedef std::function<void(prot::client::reply::readdir&)> req_cb_readdir_t;
typedef std::function<void(prot::client::reply::create&)> req_cb_create_t;

/* If the message contains data, it has a pointer to a memory region. This
 * memory region lives inside the dynamic_buffer. Hence the dynamic_buffer must
 * be kept allocated as long as the data is processed. */
typedef std::function<void(prot::client::reply::read&)> req_cb_read_t;

typedef std::function<void(prot::client::reply::write&)> req_cb_write_t;

struct request_t final
{
	uint64_t id;

	req_cb_getattr_t cb_getattr;
	req_cb_getfattr_t cb_getfattr;
	req_cb_readdir_t cb_readdir;
	req_cb_create_t cb_create;
	req_cb_read_t cb_read;
	req_cb_write_t cb_write;
};

struct com_ctrl final
{
	WrappedFD wfd;

	/* Requests */
	uint64_t next_req_id = 0;
	std::map<uint64_t, request_t> reqs;

	/* IO */
	dynamic_aligned_buffer rd_buf;
	size_t rd_buf_pos = 0;

	std::queue<queued_msg> send_queue;
	size_t send_msg_pos = 0;

	inline int get_fd()
	{
		return wfd.get_fd();
	}

	inline void set_req_id(request_t& r)
	{
		r.id = next_req_id++;
	}
};

class com_ctx final
{
protected:
	std::recursive_mutex m;

	std::list<com_ctrl> ctrls;
	std::thread worker_thread;
	bool thread_started = false;

	FileConfig cfg;
	Epoll epoll;
	EventFD evfd{
		epoll,
		std::bind_front(&com_ctx::on_evfd, this)
	};

	std::atomic<bool> quit_requested{false};

	dynamic_aligned_buffer_pool buf_pool{4096, 8};

	com_ctrl* choose_ctrl();

	void initialize_cfg();
	void initialize_connect();

	void worker_thread_func();

	/* Do never call directly except in destructor and ctrl fd handler
	 * (otherwise it might be called from the ctrl fd handler...) */
	void remove_controller(decltype(ctrls)::iterator i);
	void remove_controller(com_ctrl* cptr);

	void on_evfd();

	void on_ctrl_fd(com_ctrl* ctrl, int fd, uint32_t events);

	bool process_message(com_ctrl* ctrl, dynamic_aligned_buffer&& buf, size_t msg_len);
	bool process_message(com_ctrl* ctrl, prot::client::reply::getattr& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::getfattr& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::readdir& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::create& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::read& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::write& msg);

	bool send_message(com_ctrl* ctrl, const prot::msg& msg,
			const char* data = nullptr, size_t data_length = 0);

	bool send_message(com_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len);

public:
	com_ctx();
	~com_ctx();

	com_ctx(com_ctx&&) = delete;
	com_ctx& operator=(com_ctx&&) = delete;

	void initialize();
	void start_threads();

	void request_getattr(req_cb_getattr_t cb);
	void request_getfattr(unsigned long node_id, req_cb_getfattr_t cb);
	void request_readdir(unsigned long node_id, req_cb_readdir_t cb);
	void request_create(unsigned long parent_node_id, const char* name,
			req_cb_create_t cb);

	void request_read(unsigned long node_id, size_t offset, size_t size,
			req_cb_read_t cb);

	void request_write(unsigned long node_id, size_t offset, size_t size,
			const char* buf, req_cb_write_t cb);
};

#endif /* __COM_CTX_H */
