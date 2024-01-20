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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
}

using namespace std;


size_t inode::get_allocated_size() const
{
	size_t s = 0;
	for (auto& a : allocations)
		s += a.size;

	return s;
}

void inode::serialize(char* buf) const
{
	memset(buf, 0, 4096);
	auto ptr = buf;

	ser::swrite_u8(ptr, type);

	/* For extension-inodes in the future */
	ser::swrite_u64(ptr, 0);

	if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		ser::swrite_u64(ptr, nlink);
		ser::swrite_u64(ptr, size);
		ser::swrite_u64(ptr, mtime);

		if (name.size() > 255)
			throw invalid_argument("name length must not exceed 255 characters");

		auto namesz = name.size();
		ser::swrite_u8(ptr, namesz);
		memcpy(ptr, name.c_str(), namesz);

		/* 1+8+8+8+8+1+255 = 289 bytes; however reserve first 1k */
		ptr = buf + 1024;

		if (type == TYPE_FILE)
		{
			if (allocations.size() > 192)
				throw invalid_argument("at most 192 allocations per inode are supported");

			for (const auto& a : allocations)
			{
				ser::swrite_u64(ptr, a.offset);
				ser::swrite_u64(ptr, a.size);
			}
		}
		else
		{
			if (files.size() > 384)
				throw invalid_argument("at most 384 files per directory inode are suppored");

			for (auto f : files)
				ser::swrite_u64(ptr, f);
		}
	}
}

void inode::parse(const char* buf)
{
	auto ptr = buf;
	auto type = ser::sread_u8(ptr);

	/* For extension-inodes in the future */
	ser::sread_u64(ptr);

	if (type == TYPE_FREE)
	{
	}
	else if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		nlink = ser::sread_u64(ptr);
		size = ser::sread_u64(ptr);
		mtime = ser::sread_u64(ptr);

		char nbuf[256];
		uint8_t namesz = ser::sread_u8(ptr);
		memcpy(nbuf, ptr, namesz);
		nbuf[namesz] = '\0';
		name = string(nbuf, namesz);

		ptr = buf + 1024;

		if (type == TYPE_FILE)
		{
			allocations.clear();

			for (;;)
			{
				allocation a;
				a.offset = ser::sread_u64(ptr);
				a.size = ser::sread_u64(ptr);
				if (a.size == 0)
					break;

				allocations.push_back(a);
			}
		}
		else
		{
			files.clear();

			for (;;)
			{
				unsigned long f;
				f = ser::sread_u64(ptr);
				if (f == 0)
					break;

				files.push_back(f);
			}
		}
	}
	else
	{
		throw invalid_argument("Invalid inode type: `" + to_string(type) + "'");
	}
}

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

	for (auto& ncc : new_ctrl_conns)
		epoll.remove_fd(ncc.get_fd());

	for (auto& c : ctrls)
	{
		if (c.wfd)
			epoll.remove_fd(c.get_fd());
	}

	for (auto& dd : dds)
	{
		if (dd.wfd)
			epoll.remove_fd(dd.get_fd());
	}
}


void ctrl_ctx::remove_client(decltype(clients)::iterator i)
{
	auto c = *i;

	c->invalid = true;
	epoll.remove_fd(c->get_fd());
	c->wfd.close();

	clients.erase(i);
}

void ctrl_ctx::remove_client(shared_ptr<ctrl_client> cptr)
{
	auto i = clients.begin();
	for (;i != clients.end(); i++)
	{
		if (*i == cptr)
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
	min_ctrl_id = numeric_limits<decltype(min_ctrl_id)>::max();

	bool found = false;
	for (const auto& c : cfg.controllers)
	{
		min_ctrl_id = min(min_ctrl_id, c.id);

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

	auto& reply = static_cast<prot::dd::reply::getattr&>(*_reply);

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

	int reuseaddr = 1;
	check_syscall(
			setsockopt(sync_lfd.get_fd(), SOL_SOCKET, SO_REUSEADDR,
				&reuseaddr, sizeof(reuseaddr)),
			"setsockopt");

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

	int reuseaddr = 1;
	check_syscall(
			setsockopt(client_lfd.get_fd(), SOL_SOCKET, SO_REUSEADDR,
				&reuseaddr, sizeof(reuseaddr)),
			"setsockopt");

	addr.sin6_port = htons(SDFS_CTRL_PORT);

	check_syscall(
			bind(client_lfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"bind(client listener)");

	check_syscall(listen(client_lfd.get_fd(), 20), "listen");

	epoll.add_fd(client_lfd.get_fd(),
			EPOLLIN, bind_front(&ctrl_ctx::on_client_lfd, this));
}

void ctrl_ctx::initialize_connect_ctrls()
{
	printf("Connecting to other controllers...\n");

	/* Build list */
	for (auto& desc : cfg.controllers)
	{
		if (desc.id == id)
			continue;

		ctrls.emplace_back();
		ctrls.back().id = desc.id;
		ctrls.back().addr_str = desc.addr_str;
	}

	/* Create listening socket for other controllers */
	initialize_sync_listener();

	/* Connect */
	for (auto& c : ctrls)
	{
		/* Only connect to controllers with lower id to prevent
		 * double-connections */
		if (c.id >= id)
			continue;

		WrappedFD wfd;
		printf("  connecting to controller %u...\n", c.id);

		bool connected = false;
		unique_ptr<prot::msg> _reply;

		while (!connected && !quit_requested)
		{
			/* Resolve address and connect */
			if (regex_match(c.addr_str, regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")))
			{
				struct sockaddr_in6 addr = {
					.sin6_family = AF_INET6,
					.sin6_port = htons(SDFS_CTRL_SYNC_PORT)
				};

				if (inet_pton(AF_INET6, ("::FFFF:" + c.addr_str).c_str(),
							&addr.sin6_addr) != 1)
				{
					printf("    failed to resolve address\n");
					break;
				}

				wfd.set_errno(
						socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
						"socket");

				auto ret = connect(wfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr));
				if (ret == 0)
					connected = true;
			}
			else
			{
				struct addrinfo hints = {
					.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
					.ai_family = AF_INET6,
					.ai_socktype = SOCK_STREAM,
					.ai_protocol = 0
				};

				struct addrinfo* addrs = nullptr;

				auto gai_ret = getaddrinfo(c.addr_str.c_str(),
						nullptr, &hints, &addrs);

				if (gai_ret != 0)
				{
					printf("    failed to resolve address: %s\n",
							gai_strerror(gai_ret));

					break;
				}

				struct sockaddr_in6 addr = {
					.sin6_family = AF_INET6,
					.sin6_port = htons(SDFS_CTRL_SYNC_PORT)
				};

				try
				{
					for (struct addrinfo* ai = addrs; ai; ai = ai->ai_next)
					{
						wfd.set_errno(
								socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
								"socket");

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
			}

			if (connected)
			{
				/* Query controller info */
				prot::ctrl::req::ctrlinfo msg;
				msg.id = id;
				send_stream_msg(wfd.get_fd(), msg);

				try
				{
					_reply = receive_stream_msg<
						prot::ctrl::parse, prot::ctrl::req::CTRLINFO>
						(wfd.get_fd(), 1000);
				}
				catch (const io_timeout_exception&)
				{
					connected = false;
					wfd.close();
				}
			}
			else
			{
				epoll.process_events(1000);
			}
		}

		if (quit_requested)
			break;

		if (!connected)
			continue;

		auto& reply = static_cast<prot::ctrl::req::ctrlinfo&>(*_reply);

		/* Verify controller id */
		if (reply.id != c.id)
		{
			printf("    id mismatch (%u)\n", reply.id);
			continue;
		}

		/* Add to epoll instance */
		epoll.add_fd(wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&ctrl_ctx::on_ctrl_fd, this, &c));

		/* Set fd */
		c.wfd = move(wfd);
	}

	/* Wait for other controllers to connect */
	bool info_msg_printed = false;

	while (!quit_requested)
	{
		bool have_unconn = false;
		for (auto& c : ctrls)
		{
			if (!c.wfd)
			{
				have_unconn = true;
				break;
			}
		}

		if (!have_unconn)
			break;

		if (!info_msg_printed)
		{
			printf("  waiting for other controllers to connect...\n");
			info_msg_printed = true;
		}

		epoll.process_events(1000);
	}
}

void ctrl_ctx::initialize()
{
	/* Read config file and check values */
	initialize_cfg();

	/* Connect to dds */
	initialize_connect_dds();

	/* Build data map and initialize inode directory */
	build_data_map();
	initialize_inode_directory();

	/* Connect to other controllers */
	initialize_connect_ctrls();

	/* Create listening sockets */
	initialize_client_listener();
}


void ctrl_ctx::build_data_map()
{
	auto& dmap = data_map;

	dmap.n_dd = dds.size();
	dmap.stripe_size = dmap.block_size * dmap.n_dd;

	size_t min_dd_usable_size = dds.front().usable_size;
	for (auto& dd : dds)
	{
		min_dd_usable_size = min(min_dd_usable_size, dd.usable_size);

		dmap.dd_rr_order.push_back(&dd);
	}

	sort(dmap.dd_rr_order.begin(), dmap.dd_rr_order.end(), [](auto a, auto b) {
			return a->id < b->id;
	});

	/* Align to 1 MiB */
	min_dd_usable_size &= ~(1024ULL * 1024 - 1);

	dmap.total_size = min_dd_usable_size * dmap.n_dd;

	/* 100 MiB inode space / 4k inode size */
	dmap.total_inodes = (100 * (1024ULL * 1024)) / 4096;
}

void ctrl_ctx::initialize_inode_directory()
{
	/* Create root directory on controller with lowest id if it does not exist
	 * yet. */
	initialize_root_directory();
}

void ctrl_ctx::initialize_root_directory()
{
	if (id == min_ctrl_id)
	{
		/* Try to load root directory inode from disk */
		printf("Checking if root directory exist\n");

		/* If it does not exist, create it but do not write it to disk yet. This
		 * will happen in response to the first modification of the directory.
		 * */
		if (true)
		{
			printf("  the root directory does not exist, creating a temporary one\n\n");

			auto n = make_shared<inode>();

			n->dirty = true;
			n->type = inode::TYPE_DIRECTORY;
			n->nlink = 1;
			n->mtime = get_wt_now();

			inode_directory.cached_inodes.insert({1, n});
		}
	}
}


uint64_t ctrl_ctx::get_request_id()
{
	return next_request_id++;
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

	new_ctrl_conns.emplace_back(move(wfd));
	try
	{
		epoll.add_fd(
				new_ctrl_conns.back().get_fd(),
				EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&ctrl_ctx::on_new_ctrl_conn_fd, this));
	}
	catch (...)
	{
		new_ctrl_conns.pop_back();
		throw;
	}
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
	WrappedFD wfd;
	wfd.set_errno(accept4(fd, nullptr, nullptr, SOCK_CLOEXEC), "accept");

	auto client = make_shared<ctrl_client>();
	client->wfd = move(wfd);
	clients.emplace_back(client);

	try
	{
		epoll.add_fd(client->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&ctrl_ctx::on_client_fd, this, clients.back()));
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


void ctrl_ctx::on_client_fd(shared_ptr<ctrl_client> client, int fd, uint32_t events)
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
		shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len)
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

		case prot::client::req::GETFATTR:
			return process_client_message(
					client,
					static_cast<prot::client::req::getfattr&>(*msg));

		default:
			fprintf(stderr, "protocol violation\n");
			return true;
	}
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::getattr& msg)
{
	prot::client::reply::getattr reply;

	reply.req_id = msg.req_id;

	/* TODO */
	reply.size_total = data_map.total_size;
	reply.size_used = 0;

	reply.inodes_total = data_map.total_inodes;
	reply.inodes_used = 0;

	return send_message_to_client(client, reply);
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::getfattr& msg)
{
	if (msg.node_id == 0)
	{
		prot::client::reply::getfattr reply;
		reply.req_id = msg.req_id;
		reply.res = err::INVAL;
		send_message_to_client(client, reply);
		return false;
	}

	lock_inode(msg.node_id, [this, client, msg](int result, inode_lock_witness&& w) {
		if (result != err::SUCCESS)
		{
			prot::client::reply::getfattr reply;
			reply.req_id = msg.req_id;
			reply.res = result;
			send_message_to_client(client, reply);
		}

		/* Get inode */
		get_inode(msg.node_id, cb_get_inode_t(move(w), [this, client, msg](int result, shared_ptr<inode> node)
			{
				prot::client::reply::getfattr reply;
				reply.req_id = msg.req_id;
				reply.res = result;

				/* Add data */
				if (result == err::SUCCESS)
				{
					reply.type = node->type == inode::TYPE_FILE ?
							decltype(reply)::FT_FILE :
							decltype(reply)::FT_DIRECTORY;

					reply.nlink = node->nlink;
					reply.mtime = node->mtime;
					reply.size = node->size;
				}

				send_message_to_client(client, reply);
			}));
	});

	return false;
}


bool ctrl_ctx::send_message_to_client(shared_ptr<ctrl_client> client, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message_to_client(client, move(buf), msg_len);
}

bool ctrl_ctx::send_message_to_client(shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len)
{
	if (client->invalid)
		return true;

	auto was_empty = client->send_queue.empty();
	client->send_queue.emplace(move(buf), msg_len);

	if (was_empty)
		epoll.change_events(client->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


void ctrl_ctx::on_new_ctrl_conn_fd(int fd, uint32_t events)
{
	auto incc = find_if(new_ctrl_conns.begin(), new_ctrl_conns.end(), [fd](auto& a) {
			return a.get_fd() == fd;
	});

	if (incc == new_ctrl_conns.end())
		throw runtime_error("attempted to close new ctrl conn which is not in list");

	bool close_conn = false;
	auto nc = ctrls.end();

	if (events & (EPOLLHUP | EPOLLRDHUP))
	{
		close_conn = true;
	}
	else if (events & EPOLLIN)
	{
		try
		{
			auto _reply = receive_stream_msg<
				prot::ctrl::parse, prot::ctrl::req::CTRLINFO>
				(fd, 5000);

			auto& reply = static_cast<prot::ctrl::req::ctrlinfo&>(*_reply);

			auto i = find_if(ctrls.begin(), ctrls.end(), [&reply](auto& c) {
					return c.id == reply.id;
			});

			if (i == ctrls.end())
			{
				printf("incoming sync connection from unknown controller\n");
				close_conn = true;
			}

			if (i->wfd)
			{
				throw runtime_error("incoming sync connection for controller "
						"which is already connected");
			}

			nc = i;
		}
		catch (const io_timeout_exception&)
		{
			close_conn = true;
		}
	}

	if (close_conn)
	{
		epoll.remove_fd(fd);
		new_ctrl_conns.erase(incc);
	}
	else if (nc != ctrls.end())
	{
		epoll.remove_fd(fd);
		auto wfd(move(*incc));
		new_ctrl_conns.erase(incc);

		/* Send reply */
		prot::ctrl::req::ctrlinfo msg;
		msg.id = id;
		send_stream_msg(wfd.get_fd(), msg);

		/* Set connection */
		epoll.add_fd(wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&ctrl_ctx::on_ctrl_fd, this, &(*nc)));

		nc->wfd = move(wfd);

		printf("  accepted incoming connection from controller %u\n", nc->id);
	}
}

void ctrl_ctx::on_ctrl_fd(ctrl_ctrl* ctrl, int fd, uint32_t events)
{
	if (fd != ctrl->get_fd())
		throw runtime_error("Got epoll event for invalid fd");

	bool close_conn = false;

	/* Send data */
	if (events & EPOLLOUT)
	{
		bool disable_sender = false;
		if (ctrl->send_queue.size() > 0)
		{
			auto& qmsg = ctrl->send_queue.front();

			size_t to_write = min(
					1024UL * 1024,
					qmsg.msg_len - ctrl->send_msg_pos);

			auto ret = write(
					ctrl->get_fd(),
					qmsg.buf.ptr() + ctrl->send_msg_pos,
					to_write);

			if (ret >= 0)
			{
				ctrl->send_msg_pos += ret;
				if (ctrl->send_msg_pos == qmsg.msg_len)
				{
					ctrl->send_queue.pop();
					ctrl->send_msg_pos = 0;
					disable_sender = true;
				}
			}
			else
			{
				close_conn = true;
			}
		}
		else
		{
			disable_sender = true;
		}

		if (disable_sender)
			epoll.change_events(ctrl->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP);
	}

	/* Read data */
	if (events & EPOLLIN)
	{
		const size_t read_chunk = 8 * 1024;
		ctrl->rd_buf.ensure_size(ctrl->rd_buf_pos + read_chunk);

		auto ret = read(
				ctrl->get_fd(),
				ctrl->rd_buf.ptr() + ctrl->rd_buf_pos,
				read_chunk);

		if (ret > 0)
		{
			ctrl->rd_buf_pos += ret;

			/* Check if the message has been completely received */
			if (ctrl->rd_buf_pos >= 4)
			{
				size_t msg_len = ser::read_u32(ctrl->rd_buf.ptr());

				if (ctrl->rd_buf_pos >= msg_len + 4)
				{
					/* Move the message buffer out */
					dynamic_buffer msg_buf(move(ctrl->rd_buf));

					ctrl->rd_buf_pos -= msg_len + 4;
					ctrl->rd_buf.ensure_size(ctrl->rd_buf_pos);
					memcpy(
							ctrl->rd_buf.ptr(),
							msg_buf.ptr() + (msg_len + 4),
							ctrl->rd_buf_pos);

					/* Process the message */
					if (process_ctrl_message(ctrl, move(msg_buf), msg_len))
						close_conn = true;
				}
			}
		}
		else
		{
			close_conn = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		close_conn = true;

	if (close_conn)
		close_ctrl_conn(ctrl);
}

bool ctrl_ctx::process_ctrl_message(
		ctrl_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len)
{
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::ctrl::parse(buf.ptr() + 4, msg_len);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from ctrl: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
		case prot::ctrl::req::CTRLINFO:
			return process_ctrl_message(
					ctrl,
					static_cast<prot::ctrl::req::ctrlinfo&>(*msg));

		case prot::ctrl::req::FETCH_INODE:
			return process_ctrl_message(
					ctrl,
					static_cast<prot::ctrl::req::fetch_inode&>(*msg));

		case prot::ctrl::reply::FETCH_INODE:
			return process_ctrl_message(
					ctrl,
					static_cast<prot::ctrl::reply::fetch_inode&>(*msg));

		default:
			fprintf(stderr, "protocol violation\n");
			return true;
	}
}

bool ctrl_ctx::process_ctrl_message(
		ctrl_ctrl* ctrl, prot::ctrl::req::ctrlinfo& msg)
{
	prot::ctrl::req::ctrlinfo reply;
	reply.id = id;
	return send_message_to_ctrl(ctrl, reply);
}

bool ctrl_ctx::process_ctrl_message(
		ctrl_ctrl* ctrl, prot::ctrl::req::fetch_inode& msg)
{
	prot::ctrl::reply::fetch_inode reply;

	reply.req_id = msg.req_id;
	reply.inode = nullptr;

	/* As the controller is single threaded we can access the inode cache here
	 * without a lock. As for the general state of the (cached) inode, the
	 * request will hold a lock. Maybe an write lock requests is also present,
	 * but it will not have been granted throughout the cluster yet. */
	auto i = inode_directory.cached_inodes.find(msg.node_id);
	if (i != inode_directory.cached_inodes.end())
	{
		auto in = i->second;

		fixed_buffer ib(4096);
		in->serialize(ib.ptr());

		reply.inode = ib.ptr();
		return send_message_to_ctrl(ctrl, reply);
	}

	return send_message_to_ctrl(ctrl, reply);
}

bool ctrl_ctx::process_ctrl_message(
		ctrl_ctrl* ctrl, prot::ctrl::reply::fetch_inode& msg)
{
	/* Find request */
	auto ireq = inode_requests.find(msg.req_id);
	if (ireq == inode_requests.end())
		throw runtime_error("received invalid fetch inode reply");

	auto& req = ireq->second;

	/* Parse inode */
	shared_ptr<inode> in;
	if (msg.inode)
	{
		in = make_shared<inode>();
		in->parse(msg.inode);

		printf("fetched inode from other controller\n");
	}

	/* Answer request */
	req.cb(in);
	inode_requests.erase(ireq);

	return false;
}

bool ctrl_ctx::send_message_to_ctrl(ctrl_ctrl* ctrl, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message_to_ctrl(ctrl, move(buf), msg_len);
}

bool ctrl_ctx::send_message_to_ctrl(ctrl_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len)
{
	auto was_empty = ctrl->send_queue.empty();
	ctrl->send_queue.emplace(move(buf), msg_len);

	if (was_empty)
		epoll.change_events(ctrl->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}

void ctrl_ctx::close_ctrl_conn(ctrl_ctrl* ctrl)
{
	if (ctrl->wfd)
		epoll.remove_fd(ctrl->get_fd());

	ctrl->wfd.close();

	throw runtime_error("Lost connection to controller " + to_string(ctrl->id));
}


void ctrl_ctx::lock_inode(unsigned long node_id, cb_lock_inode_t cb)
{
	if (node_id == 0)
		throw invalid_argument("node_id must not be 0");

	/* If this is a read lock and currently there is no write lock, grant it */
	bool grant = false;

	auto i = inode_directory.node_locks.find(node_id);
	if (i == inode_directory.node_locks.end())
	{
		grant = true;
		inode_directory.node_locks.insert({node_id, 1});
	}
	else if (i->second > 0)
	{
		grant = true;
		i->second++;
	}

	if (grant)
	{
		printf("LOCK INODE %lu r\n", node_id);

		cb(err::SUCCESS, inode_lock_witness(*this, node_id));
		return;
	}

	/* Otherwise create a lock request */

	/* Send the lock request to the other controllers */
}

/* Must be called with at least lock on the inode (a witness is required in cb) */
void ctrl_ctx::get_inode(unsigned long node_id, cb_get_inode_t&& cb)
{
	if (node_id == 0)
		throw invalid_argument("node_id must not be 0");

	cb.assert_lock();

	shared_ptr<inode> n;

	/* Check if the inode is cached */
	auto i = inode_directory.cached_inodes.find(node_id);
	if (i != inode_directory.cached_inodes.end())
	{
		cb(err::SUCCESS, i->second);
		return;
	}

	/* If not, try to fetch the inode from a different controller */
	fetch_inode_from_ctrls(node_id, cb_fetch_inode_from_ctrls_t(move(cb),
		[this, node_id](cb_get_inode_t&& cb, shared_ptr<inode> in) {
			if (in)
			{
				/* Insert inode into cache */
				inode_directory.cached_inodes.insert_or_assign(node_id, in);

				cb(err::SUCCESS, in);
				return;
			}

			/* Try to fetch the inode from disk */

			/* Return inode or NOENT */
			cb(err::NOENT, nullptr);
		}));
}

/* Must be called with at least a read lock on the inode number; if the inode
 * could not be retrieved, nullptr is passed to the cb */
void ctrl_ctx::fetch_inode_from_ctrls(unsigned long node_id, cb_fetch_inode_from_ctrls_t&& cb)
{
	for (auto& c : ctrls)
	{
		if (c.id == id)
			continue;

		/* Generate request */
		inode_request_t r(get_request_id(), node_id, move(cb));
		auto [i,inserted] = inode_requests.emplace(r.req_id, move(r));
		if (!inserted)
			throw runtime_error("request id conflict");

		/* Send request to controller */
		prot::ctrl::req::fetch_inode msg;

		msg.req_id = r.req_id;
		msg.node_id = node_id;

		send_message_to_ctrl(&c, msg);

		/* Support only two-controller scenario for now (follow-up request would
		 * have to be sent in reply to the response; hence the request would
		 * need carry information about which controllers have been contacted
		 * yet). */
		return;
	}

	cb(nullptr);
}


void ctrl_ctx::main()
{
	while (!quit_requested)
		epoll.process_events(-1);
}


inode_lock_witness::inode_lock_witness()
	: ctrl(nullptr), node_id(0)
{
}

inode_lock_witness::inode_lock_witness(ctrl_ctx& ctrl, unsigned long node_id)
	: ctrl(&ctrl), node_id(node_id)
{
}

inode_lock_witness::inode_lock_witness(inode_lock_witness&& o)
	: ctrl(o.ctrl), node_id(o.node_id)
{
	o.node_id = 0;
}

inode_lock_witness& inode_lock_witness::operator=(inode_lock_witness&& o)
{
	clean();

	ctrl = o.ctrl;
	node_id = o.node_id;

	o.node_id = 0;

	return *this;
}

inode_lock_witness::~inode_lock_witness()
{
	clean();
}

void inode_lock_witness::clean()
{
	if (node_id > 0)
	{
		printf("UNLOCK INODE %lu\n", node_id);

		/* Remove lock */
		auto i = ctrl->inode_directory.node_locks.find(node_id);
		if (i->second > 1)
		{
			i->second--;
		}
		else
		{
			/* Grant other pending locks (must be either write locks or the first
			 * read lock after a write lock) */
			if (false)
			{
				printf("LOCK INODE %lu r\n", node_id);
			}
			else
			{
				ctrl->inode_directory.node_locks.erase(i);
			}
		}
	}
}

bool inode_lock_witness::lock_held() const
{
	return node_id != 0;
}
