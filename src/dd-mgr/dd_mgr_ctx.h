#ifndef __DD_MGR_CTX_H
#define __DD_MGR_CTX_H

#include <vector>
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/prot_dd_mgr.h"

struct dd_mgr_dd final
{
	WrappedFD fd;

	unsigned id = 0;
	int port = 0;

	bool registered = false;

	dd_mgr_dd(WrappedFD&& fd);
	int get_fd();
};

struct dd_mgr_client final
{
	WrappedFD fd;
	char read_buf[8192];
	size_t read_buf_pos = 0;

	dd_mgr_client(WrappedFD&& fd);
	int get_fd();
};

class dd_mgr_ctx final
{
protected:
	bool quit_requested = false;

	Epoll epoll;

	SignalFD sfd{
		{SIGINT, SIGTERM},
		epoll,
		std::bind_front(&dd_mgr_ctx::on_signal, this)};

	WrappedFD ufd;
	WrappedFD tfd;

	std::vector<dd_mgr_dd> dds;
	std::vector<dd_mgr_client> clients;

	void initialize_unix_socket();
	void initialize_tcp();

	void on_signal(int s);

	void on_dd_conn(int fd, uint32_t events);
	void on_dd_fd(int fd, uint32_t events);

	bool process_dd_message(dd_mgr_dd& dd, const prot::msg& msg);
	bool process_dd_message(dd_mgr_dd& dd, const prot::dd_mgr_be::req::register_dd& msg);

	void on_client_conn(int fd, uint32_t events);
	void on_client_fd(int fd, uint32_t events);

	bool process_client_message(dd_mgr_client& c, const char* buf, size_t size);
	bool process_client_message(dd_mgr_client& c, const prot::dd_mgr_fe::req::query_dds& msg);

	bool send_to_client(dd_mgr_client& c, const prot::msg& msg);

public:
	~dd_mgr_ctx();

	void initialize();

	void main();
};

#endif /* __DD_MGR_CTX_H */
