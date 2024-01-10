#include <cstring>
#include <algorithm>
#include <regex>
#include "config.h"
#include "ctrl_ctx.h"
#include "common/exceptions.h"
#include "common/prot_dd_mgr.h"
#include "common/prot_dd.h"
#include "common/msg_utils.h"
#include "common/serialization.h"

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
}

using namespace std;


ctrl_ctx::ctrl_ctx(unsigned id, const optional<const string>& bind_addr)
	: id(id), bind_addr_str(bind_addr)
{
}

ctrl_ctx::~ctrl_ctx()
{
	if (client_lfd)
		epoll.remove_fd_ignore_unknown(client_lfd.get_fd());

	if (sync_lfd)
		epoll.remove_fd_ignore_unknown(sync_lfd.get_fd());

	while (clients.size() > 0)
		remove_client(clients.begin());

	for (auto& dd : dds)
	{
		if (dd.wfd)
			epoll.remove_fd(dd.wfd.get_fd());
	}
}


void ctrl_ctx::remove_client(list<ctrl_client>::iterator i)
{
	auto& c = *i;

	epoll.remove_fd(c.get_fd());

	clients.erase(i);
}

void ctrl_ctx::remove_client(ctrl_client* cptr)
{
	auto i = clients.begin();
	for (;i != clients.end(); i++)
	{
		if (&(*i) == cptr)
			break;
	}

	if (i == clients.end())
		throw invalid_argument("no such client in client list");

	remove_client(i);
}


void ctrl_ctx::print_cfg()
{
	printf("\nUsing the following configuration:\n");

	for (const auto& c : cfg.controllers)
		printf("  controller: %u (on host %s)\n", c.id, c.addr_str.c_str());

	for (const auto& dd : cfg.dds)
		printf("  dd: %u (gid: %s)\n", dd.id, dd.gid.c_str());

	for (const auto& ddh : cfg.dd_hosts)
		printf("  dd-host: %s\n", ddh.addr_str.c_str());

	printf("\n");
}

void ctrl_ctx::initialize_cfg()
{
	cfg = read_sdfs_config_file();
	print_cfg();

	/* Check that this controller's id appears in the configuration file */
	bool found = false;
	for (const auto& c : cfg.controllers)
	{
		if (c.id == id)
		{
			found = true;
			break;
		}
	}

	if (!found)
		throw runtime_error("This controller is not listed in the config file");

	/* Check that at least one dd and at least one dd host are defined */
	if (cfg.dds.size() <= 0 || cfg.dd_hosts.size() <= 0)
		throw runtime_error("At least one dd and dd-host must be defined");

	printf("controller id: %u\n\n", id);
}

void ctrl_ctx::initialize_dd_host(const string& addr_str)
{
	printf("Connecting to dd-host %s...\n", addr_str.c_str());

	/* Resolve address and try to connect */
	WrappedFD wfd;

	struct addrinfo hints = {
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
		.ai_family = AF_INET6,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0
	};

	struct addrinfo* addrs = nullptr;

	auto gai_ret = getaddrinfo(addr_str.c_str(), nullptr, &hints, &addrs);
	if (gai_ret != 0)
	{
		throw gai_exception(gai_ret, "Failed to resolve dd-host address `" +
				addr_str + "': ");
	}

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(SDFS_DD_MGR_PORT)
	};

	bool connected = false;

	try
	{
		for (struct addrinfo* ai = addrs; ai; ai = ai->ai_next)
		{
			wfd.set_errno(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0), "socket");

			addr.sin6_addr = ((const struct sockaddr_in6&) ai->ai_addr).sin6_addr;

			auto ret = connect(wfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr));
			if (ret == 0)
			{
				connected = true;
				break;
			}
		}

		freeaddrinfo(addrs);
	}
	catch (...)
	{
		freeaddrinfo(addrs);
		throw;
	}

	if (!connected)
		throw runtime_error("Failed to connect to dd-host `" + addr_str + "'");


	/* List dds */
	send_stream_msg(wfd.get_fd(), prot::dd_mgr_fe::req::query_dds());
	auto reply = receive_stream_msg<prot::dd_mgr_fe::reply::parse,
		 (unsigned) prot::dd_mgr_fe::reply::msg_nums::QUERY_DDS>(
			wfd.get_fd(), 5000);

	for (const auto& desc : static_cast<prot::dd_mgr_fe::reply::query_dds&>(*reply).dds)
	{
		for (auto& dd : dds)
		{
			if (dd.id == desc.id)
			{
				if (desc.port < SDFS_DD_PORT_START || desc.port > SDFS_DD_PORT_END)
					throw runtime_error("Received invalid dd port");

				dd.port = desc.port;
				initialize_connect_dd(addr.sin6_addr, dd);
				break;
			}
		}
	}

	printf("\n");
}

void ctrl_ctx::initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd)
{
	printf("  connecting to dd %u...\n", dd.id);

	WrappedFD wfd;
	wfd.set_errno(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0), "socket");

	sockaddr_in6 saddr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(dd.port),
		.sin6_addr = addr
	};

	check_syscall(
			connect(wfd.get_fd(), (const struct sockaddr*) &saddr, sizeof(saddr)),
			"connect(dd)");

	/* Query dd parameters */
	send_stream_msg(wfd.get_fd(), prot::dd::req::getattr());
	auto _reply = receive_stream_msg<prot::dd::reply::parse, prot::dd::reply::GETATTR>
			(wfd.get_fd(), 5000);

	auto reply = static_cast<prot::dd::reply::getattr&>(*_reply);

	/* Ensure id and guid match */
	if (dd.id != reply.id)
	{
		printf("    invalid id (%u)\n", reply.id);
		return;
	}

	if (memcmp(dd.gid, reply.gid, sizeof(dd.gid)) != 0)
	{
		printf("    gid mismatch\n");
		return;
	}

	/* Ensure sizes are correct */
	if (reply.usable_size > reply.size - (4096 + 101 * 1024 * 1024))
	{
		printf("    usable size seems too large\n");
		return;
	}

	/* populate ctrl_dd structure */
	dd.size = reply.size;
	dd.usable_size = reply.usable_size;

	epoll.add_fd(wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
			bind_front(&ctrl_ctx::on_dd_fd, this));

	dd.wfd = move(wfd);
	dd.connected = true;
}

void ctrl_ctx::initialize_connect_dds()
{
	/* Build dd list */
	for (const auto& cd : cfg.dds)
	{
		dds.emplace_back();
		ctrl_dd& dd = dds.back();
		dd.id = cd.id;
		parse_gid(dd.gid, cd.gid);
	}

	/* Connect to dd hosts and to corresponding dds */
	for (const auto& ddh : cfg.dd_hosts)
		initialize_dd_host(ddh.addr_str);

	/* Check if all dds are connected */
	bool have_unconnected = false;
	printf("dd status:\n");
	for (auto& dd : dds)
	{
		printf("  %u: %s\n", dd.id, (dd.connected ? "conn" : "unconn"));

		if (!dd.connected)
			have_unconnected = true;
	}

	printf("\n");

	if (have_unconnected)
		throw runtime_error("unconnected dds present");
}


struct sockaddr_in6 determine_bind_address(const optional<const string>& bind_addr_str)
{
	struct sockaddr_in6 addr{};

	/* Determine bind address */
	if (bind_addr_str)
	{
		if (bind_addr_str == "localhost")
		{
			addr.sin6_addr = in6addr_loopback;
		}
		else if (regex_match(bind_addr_str->c_str(),
					regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")))
		{
			string mod = "::FFFF:" + *bind_addr_str;
			if (inet_pton(AF_INET6, mod.c_str(), &addr.sin6_addr) != 1)
				throw invalid_argument("Invalid bind address");
		}
		else
		{
			if (inet_pton(AF_INET6, bind_addr_str->c_str(), &addr.sin6_addr) != 1)
				throw invalid_argument("Invalid bind address");
		}
	}
	else
	{
		addr.sin6_addr = in6addr_any;
	}

	addr.sin6_family = AF_INET6;

	return addr;
}

void ctrl_ctx::initialize_sync_listener()
{
	auto addr = determine_bind_address(bind_addr_str);

	/* Create sync socket */
	sync_lfd.set_errno(
			socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
			"socket");

	addr.sin6_port = htons(SDFS_CTRL_SYNC_PORT);

	check_syscall(
			bind(sync_lfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"bind(sync listener");

	check_syscall(listen(sync_lfd.get_fd(), 5), "listen");

	epoll.add_fd(sync_lfd.get_fd(),
			EPOLLIN, bind_front(&ctrl_ctx::on_sync_lfd, this));
}

void ctrl_ctx::initialize_client_listener()
{
	auto addr = determine_bind_address(bind_addr_str);

	/* Create client socket */
	client_lfd.set_errno(
			socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
			"socket");

	addr.sin6_port = htons(SDFS_CTRL_PORT);

	check_syscall(
			bind(client_lfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"bind(client listener)");

	check_syscall(listen(client_lfd.get_fd(), 20), "listen");

	epoll.add_fd(client_lfd.get_fd(),
			EPOLLIN, bind_front(&ctrl_ctx::on_client_lfd, this));
}

void ctrl_ctx::initialize()
{
	/* Read config file and check values */
	initialize_cfg();

	/* Connect to dds */
	initialize_connect_dds();

	/* Build data map */

	/* Create listening socket for other controllers */
	initialize_sync_listener();

	/* Connect to other controllers */

	/* Create listening sockets */
	initialize_client_listener();
}


void ctrl_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
	{
		quit_requested = true;
	}
}


void ctrl_ctx::on_sync_lfd(int fd, uint32_t events)
{
	WrappedFD wfd;
	wfd.set_errno(accept4(fd, nullptr, nullptr, SOCK_CLOEXEC), "accept");
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
	WrappedFD wfd;
	wfd.set_errno(accept4(fd, nullptr, nullptr, SOCK_CLOEXEC), "accept");

	clients.emplace_back();
	clients.back().wfd = move(wfd);

	try
	{
		epoll.add_fd(clients.back().get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&ctrl_ctx::on_client_fd, this, &clients.back()));
	}
	catch (...)
	{
		clients.pop_back();
		throw;
	}
}


void ctrl_ctx::on_dd_fd(int fd, uint32_t events)
{
}


void ctrl_ctx::on_client_fd(ctrl_client* client, int fd, uint32_t events)
{
	if (fd != client->get_fd())
		throw runtime_error("Got epoll event for invalid fd");

	bool rm_client = false;

	/* Send data */
	if (events & EPOLLOUT)
	{
		bool disable_sender = false;
		if (client->send_queue.size() > 0)
		{
			auto& qmsg = client->send_queue.front();

			size_t to_write = min(
					1024UL * 1024,
					qmsg.msg_len - client->send_msg_pos);

			auto ret = write(
					client->get_fd(),
					qmsg.buf.ptr() + client->send_msg_pos,
					to_write);

			if (ret >= 0)
			{
				client->send_msg_pos += ret;
				if (client->send_msg_pos == qmsg.msg_len)
				{
					client->send_queue.pop();
					client->send_msg_pos = 0;
					disable_sender = true;
				}
			}
			else
			{
				rm_client = true;
			}
		}
		else
		{
			disable_sender = true;
		}

		if (disable_sender)
			epoll.change_events(client->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP);
	}

	/* Read data */
	if (events & EPOLLIN)
	{
		const size_t read_chunk = 100 * 1024;
		client->rd_buf.ensure_size(client->rd_buf_pos + read_chunk);

		auto ret = read(
				client->get_fd(),
				client->rd_buf.ptr() + client->rd_buf_pos,
				read_chunk);

		if (ret > 0)
		{
			client->rd_buf_pos += ret;

			/* Check if the message has been completely received */
			if (client->rd_buf_pos >= 4)
			{
				size_t msg_len = ser::read_u32(client->rd_buf.ptr());

				if (client->rd_buf_pos >= msg_len + 4)
				{
					/* Move the message buffer out */
					dynamic_buffer msg_buf(move(client->rd_buf));

					client->rd_buf_pos -= msg_len + 4;
					client->rd_buf.ensure_size(client->rd_buf_pos);
					memcpy(
							client->rd_buf.ptr(),
							msg_buf.ptr() + (msg_len + 4),
							client->rd_buf_pos);

					/* Process the message */
					if (process_client_message(client, move(msg_buf), msg_len))
						rm_client = true;
				}
			}
		}
		else
		{
			rm_client = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		rm_client = true;

	if (rm_client)
		remove_client(client);
}

bool ctrl_ctx::process_client_message(
		ctrl_client* client, dynamic_buffer&& buf, size_t msg_len)
{
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::client::req::parse(buf.ptr() + 4, msg_len);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from client: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
		case prot::client::req::GETATTR:
			return process_client_message(
					client,
					static_cast<prot::client::req::getattr&>(*msg));

		default:
			fprintf(stderr, "protocol violation\n");
			return true;
	}
}

bool ctrl_ctx::process_client_message(
		ctrl_client* client, prot::client::req::getattr& msg)
{
	prot::client::reply::getattr reply;

	return send_message_to_client(client, reply);
}

bool ctrl_ctx::send_message_to_client(ctrl_client* client, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message_to_client(client, move(buf), msg_len);
}

bool ctrl_ctx::send_message_to_client(ctrl_client* client, dynamic_buffer&& buf, size_t msg_len)
{
	auto was_empty = client->send_queue.empty();
	client->send_queue.emplace(move(buf), msg_len);

	if (was_empty)
		epoll.change_events(client->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


void ctrl_ctx::main()
{
	while (!quit_requested)
		epoll.process_events(-1);
}
