#ifndef __CTRL_CTX_H
#define __CTRL_CTX_H

#include <string>
#include <optional>
#include <list>
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"

extern "C" {
#include <netinet/in.h>
}

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

class ctrl_ctx final
{
protected:
	const unsigned id;
	const std::optional<const std::string> bind_addr_str;

	FileConfig cfg;

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

	void print_cfg();

	void initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_listeners();

	void on_signal(int s);

	void on_sync_lfd(int fd, uint32_t events);
	void on_client_lfd(int fd, uint32_t events);

	void on_dd_fd(int fd, uint32_t events);

public:
	ctrl_ctx(unsigned id, const std::optional<const std::string>& bind_addr);
	~ctrl_ctx();

	void initialize();

	void main();
};

#endif /* __CTRL_CTX_H */
