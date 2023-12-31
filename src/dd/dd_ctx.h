#ifndef __DD_CTX_H
#define __DD_CTX_H

#include <string>
#include <vector>
#include "common/utils.h"
#include "common/io_uring.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "utils.h"

/* Connections from controllers */
class dd_client final
{
protected:
	WrappedFD wfd;

public:
	dd_client(int fd);
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
	std::vector<dd_client> clients;

	void initialize_sock();
	void initialize_mgr();

	void on_signal(int s);
	void on_listen_sock(int fd, uint32_t events);

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
