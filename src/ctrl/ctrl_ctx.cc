#include "config.h"
#include <regex>
#include "ctrl_ctx.h"
#include "common/exceptions.h"
#include "common/prot_dd_mgr.h"
#include "common/prot_dd.h"
#include "common/msg_utils.h"

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

	for (auto& dd : dds)
	{
		if (dd.wfd)
			epoll.remove_fd(dd.wfd.get_fd());
	}
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

void ctrl_ctx::initialize_listeners()
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

	/* Connect to other controllers */

	/* Create listening sockets */
	initialize_listeners();
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
	auto cfd = check_syscall(
			accept4(fd, nullptr, nullptr, SOCK_CLOEXEC),
			"accept");

	close(cfd);
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
}


void ctrl_ctx::on_dd_fd(int fd, uint32_t events)
{
}


void ctrl_ctx::main()
{
	while (!quit_requested)
		epoll.process_events(-1);
}
