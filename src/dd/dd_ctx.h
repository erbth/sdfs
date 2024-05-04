#ifndef __DD_CTX_H
#define __DD_CTX_H

#include <string>
#include <memory>
#include <vector>
#include <list>
#include <optional>
#include <queue>
#include <variant>
#include "common/utils.h"
#include "common/io_uring.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/dynamic_buffer.h"
#include "common/prot_dd.h"
#include "utils.h"


struct dd_queued_msg final
{
	std::variant<dynamic_buffer, dynamic_aligned_buffer> vbuf;
	const size_t msg_len;

	inline dd_queued_msg(
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


/* Connections from controllers */
struct dd_client final
{
	/* After a client was removed from the list but is still kept alive through
	 * a shared_ptr */
	bool invalid = false;

	WrappedFD wfd;

	/* Receive messages */
	dynamic_aligned_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Send messages */
	std::queue<dd_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};

class dd_ctx final
{
public:
	const unsigned max_ios_in_flight = 256;

protected:
	WrappedFD wfd;
	DeviceInfo di;

	Epoll epoll;
	SignalFD sfd{
		{SIGINT, SIGTERM},
		epoll,
		std::bind(&dd_ctx::on_signal, this, std::placeholders::_1)};

	/* NOTE: Epoll comes before because IOUring polls epoll's filedescriptor */
	IOUring io_uring{next_power_of_two(max_ios_in_flight + 1)};

	int port = 0;
	WrappedFD sock;

	WrappedFD mgr_sock;

	bool quit_requested = false;

	/* Clients */
	std::vector<std::shared_ptr<dd_client>> clients;

	/* Be careful when calling these functions */
	void remove_client(decltype(clients)::iterator i);
	void remove_client(std::shared_ptr<dd_client> client);

	void initialize_sock();
	void initialize_mgr();

	void on_signal(int s);
	void on_listen_sock(int fd, uint32_t events);

	/* Buffer pool for requests */
	dynamic_aligned_buffer_pool buf_pool_client{4096, 8};

	void on_client_fd(std::shared_ptr<dd_client> client, int fd, uint32_t events);

	bool process_client_message(std::shared_ptr<dd_client> client, dynamic_aligned_buffer&& buf, size_t msg_len);
	bool process_client_message(std::shared_ptr<dd_client> client, const prot::dd::req::getattr& msg);
	bool process_client_message(std::shared_ptr<dd_client> client, const prot::dd::req::read& msg);

	bool send_message_to_client(std::shared_ptr<dd_client> client, const prot::msg& msg);
	bool send_message_to_client(std::shared_ptr<dd_client> client,
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len);

	/* io uring event handlers */
	void on_epoll_ready(int res);

public:
	const std::string device_file;

	dd_ctx(const std::string& device_file);
	~dd_ctx();

	void initialize();
	void main();
};

#endif /* __DD_CTX_H */
