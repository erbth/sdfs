#ifndef __CTRL_CTX_H
#define __CTRL_CTX_H

#include <string>
#include <optional>
#include <list>
#include <vector>
#include <map>
#include <queue>
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"

extern "C" {
#include <netinet/in.h>
}


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

	/* clients */
	std::list<ctrl_client> clients;

	/* data map */
	data_map_t data_map;

	void remove_client(decltype(clients)::iterator i);
	void remove_client(ctrl_client* client);

	void print_cfg();

	void initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_sync_listener();
	void initialize_client_listener();

	void build_data_map();

	void on_signal(int s);

	void on_sync_lfd(int fd, uint32_t events);
	void on_client_lfd(int fd, uint32_t events);

	void on_dd_fd(int fd, uint32_t events);
	void on_client_fd(ctrl_client* client, int fd, uint32_t events);

	bool process_client_message(ctrl_client* client, dynamic_buffer&& buf, size_t msg_len);
	bool process_client_message(ctrl_client* client, prot::client::req::getattr& msg);

	bool send_message_to_client(ctrl_client* client, const prot::msg& msg);
	bool send_message_to_client(ctrl_client* client, dynamic_buffer&& buf, size_t msg_len);

public:
	ctrl_ctx(unsigned id, const std::optional<const std::string>& bind_addr);
	~ctrl_ctx();

	void initialize();

	void main();
};

#endif /* __CTRL_CTX_H */
