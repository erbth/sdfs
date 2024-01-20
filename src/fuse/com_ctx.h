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

struct request_t final
{
	uint64_t id;

	req_cb_getattr_t cb_getattr;
	req_cb_getfattr_t cb_getfattr;
};

struct com_ctrl final
{
	unsigned id;
	WrappedFD wfd;

	/* Requests */
	uint64_t next_req_id = 0;
	std::map<uint64_t, request_t> reqs;

	/* IO */
	dynamic_buffer rd_buf;
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
	std::mutex m;

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

	unsigned next_ctrl = 0;
	com_ctrl* choose_ctrl();

	void initialize_cfg();
	void initialize_connect();

	void worker_thread_func();

	void remove_controller(decltype(ctrls)::iterator i);
	void remove_controller(com_ctrl* cptr);

	void on_evfd();

	void on_ctrl_fd(com_ctrl* ctrl, int fd, uint32_t events);

	bool process_message(com_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len);
	bool process_message(com_ctrl* ctrl, prot::client::reply::getattr& msg);
	bool process_message(com_ctrl* ctrl, prot::client::reply::getfattr& msg);

	bool send_message(com_ctrl* ctrl, const prot::msg& msg);
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
};

#endif /* __COM_CTX_H */
