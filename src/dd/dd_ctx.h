#ifndef __DD_CTX_H
#define __DD_CTX_H

#include <string>
#include <memory>
#include <vector>
#include <list>
#include <optional>
#include "common/utils.h"
#include "common/io_uring.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/fixed_buffer.h"
#include "common/dynamic_buffer.h"
#include "common/prot_dd.h"
#include "utils.h"

/* Connections from controllers */
struct dd_client final
{
	WrappedFD wfd;

	dynamic_buffer rd_buf;
	size_t rd_buf_pos = 0;

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

	void initialize_sock();
	void initialize_mgr();

	void on_signal(int s);
	void on_listen_sock(int fd, uint32_t events);

	void on_client_fd(std::shared_ptr<dd_client> client, int fd, uint32_t events);

	bool process_client_message(std::shared_ptr<dd_client> client,
			dynamic_buffer&& buf, size_t msg_len);

	bool process_client_message(std::shared_ptr<dd_client> client,
			const prot::dd::req::getattr& msg);

	bool send_to_client(std::shared_ptr<dd_client> client,
			std::shared_ptr<prot::msg> msg,
			std::optional<fixed_aligned_buffer>&& buf);

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
