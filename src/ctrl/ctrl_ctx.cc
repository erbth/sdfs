#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <regex>
#include "config.h"
#include "ctrl_ctx.h"
#include "common/exceptions.h"
#include "common/prot_dd_mgr.h"
#include "common/prot_dd.h"
#include "common/msg_utils.h"
#include "common/serialization.h"
#include "common/strformat.h"
#include "common/profiler.h"
#include "common/protocols.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
}

using namespace std;


ctrl_ctx::ctrl_ctx()
{
}

ctrl_ctx::~ctrl_ctx()
{
	if (client_lfd)
		ep.remove_fd_ignore_unknown(client_lfd.get_fd());

	for (auto& dd : dds)
	{
		if (dd.wfd)
			ep.remove_fd(dd.get_fd());
	}
}


void ctrl_ctx::print_cfg()
{
	printf("\nUsing the following configuration:\n");

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

	/* Check that at least one dd and at least one dd host are defined */
	if (cfg.dds.size() <= 0 || cfg.dd_hosts.size() <= 0)
		throw runtime_error("At least one dd and dd-host must be defined");
}

pair<WrappedFD, struct sockaddr_in6> ctrl_ctx::initialize_dd_host(const string& addr_str)
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
		while (!connected && !quit_requested)
		{
			for (struct addrinfo* ai = addrs; ai; ai = ai->ai_next)
			{
				wfd.set_errno(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0), "socket");

				addr.sin6_addr = ((const struct sockaddr_in6*) ai->ai_addr)->sin6_addr;

				auto ret = connect(wfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr));
				if (ret == 0)
				{
					connected = true;
					break;
				}
			}

			if (!connected)
				sfd.check(1000);
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

	return make_pair(move(wfd), addr);
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
	auto reply = receive_stream_msg<
		prot::dd::reply::getattr,
		prot::dd::reply::parse>
			(wfd.get_fd(), 30000);

	/* Ensure id and guid match */
	if (dd.id != reply->id)
	{
		printf("    invalid id (%u)\n", reply->id);
		return;
	}

	if (memcmp(dd.gid, reply->gid, sizeof(dd.gid)) != 0)
	{
		printf("    gid mismatch\n");
		return;
	}

	/* populate ctrl_dd structure */
	dd.size = reply->size;
	printf("    size: %s (%lu B), raw size: %s (%lu B)\n",
			format_size_bin(reply->size).c_str(), (long unsigned) reply->size,
			format_size_bin(reply->raw_size).c_str(), (long unsigned) reply->raw_size);

	ep.add_fd(wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
			bind_front(&ctrl_ctx::on_dd_fd, this, &dd));

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
	vector<pair<WrappedFD, struct sockaddr_in6>> ddh_conns;
	for (const auto& ddh : cfg.dd_hosts)
		ddh_conns.emplace_back(move(initialize_dd_host(ddh.addr_str)));

	/* Connect to dds - this means waiting until all dds appear at dd hosts and
	 * connecting to them. */
	map<unsigned, int> connected_dds_hosts;
	bool have_unconnected = true;

	printf("Waiting for dds...\n");

	bool change = true;
	while (!quit_requested)
	{
		for (auto& [ddh_conn, addr] : ddh_conns)
		{
			/* List dds */
			send_stream_msg(ddh_conn.get_fd(), prot::dd_mgr_fe::req::query_dds());
			auto reply = receive_stream_msg<
				prot::dd_mgr_fe::reply::query_dds,
				prot::dd_mgr_fe::reply::parse
					>(ddh_conn.get_fd(), 30000);

			for (const auto& desc : reply->dds)
			{
				for (auto& dd : dds)
				{
					if (dd.id == desc.id)
					{
						if (desc.port < SDFS_DD_PORT_START || desc.port > SDFS_DD_PORT_END)
							throw runtime_error("Received invalid dd port");

						if (dd.wfd)
						{
							auto ref = connected_dds_hosts.find(dd.id);
							if (
									dd.port != desc.port ||
									(ref != connected_dds_hosts.end() && ref->second != ddh_conn.get_fd())
							   )
							{
								printf("  ignoring duplicate dd (different host/port): %u\n", dd.id);
							}

							continue;
						}

						dd.port = desc.port;
						initialize_connect_dd(addr.sin6_addr, dd);

						connected_dds_hosts.emplace(dd.id, ddh_conn.get_fd());
						change = true;
						break;
					}
				}
			}
		}

		if (change)
		{
			/* Check if all dds are connected */
			bool all_connected = true;
			printf("\ndd status:\n");
			for (auto& dd : dds)
			{
				printf("  %u: %s\n", dd.id, (dd.connected ? "conn" : "unconn"));

				if (!dd.connected)
					all_connected = false;
			}

			printf("\n");

			if (all_connected)
			{
				have_unconnected = false;
				break;
			}
		}

		change = false;
		sfd.check(1000);
	}

	if (have_unconnected)
		throw runtime_error("unconnected dds present");
}


void ctrl_ctx::initialize_data_map()
{
	size_t min_dd_size = numeric_limits<size_t>::max();
	for (auto& dd : dds)
	{
		min_dd_size = min(dd.size & ~(1024 * 1024 - 1UL), min_dd_size);
		data_map.dd_order.push_back(&dd);
	}

	auto total_size = min_dd_size * data_map.dd_order.size();

	data_map.cnt_blocks = total_size / data_map.block_size;
	data_map.size = data_map.cnt_blocks * data_map.block_size;
}


void ctrl_ctx::initialize_client_listener()
{
	/* Create client socket */
	client_lfd.set_errno(
			socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
			"socket");

	int reuseaddr = 1;
	check_syscall(
			setsockopt(client_lfd.get_fd(), SOL_SOCKET, SO_REUSEADDR,
				&reuseaddr, sizeof(reuseaddr)),
			"setsockopt");

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(SDFS_CTRL_PORT),
		.sin6_addr = IN6ADDR_ANY_INIT
	};

	check_syscall(
			bind(client_lfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"bind(client listener)");

	check_syscall(listen(client_lfd.get_fd(), 20), "listen");

	ep.add_fd(client_lfd.get_fd(),
			EPOLLIN, bind_front(&ctrl_ctx::on_client_lfd, this));
}

void ctrl_ctx::initialize()
{
	/* Read config file and check values */
	initialize_cfg();

	/* Connect to dds */
	initialize_connect_dds();

	/* Compute data map */
	initialize_data_map();

	/* Create listening socket for client */
	initialize_client_listener();
}


uint64_t ctrl_ctx::get_request_id()
{
	return next_request_id++;
}

void ctrl_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		quit_requested = true;
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
	struct sockaddr_in6 addr{};
	socklen_t addrlen = sizeof(addr);

	WrappedFD wfd;
	wfd.set_errno(
			accept4(fd, (struct sockaddr*) &addr, &addrlen, SOCK_CLOEXEC),
			"accept");

	printf("New client-connection from %s\n", in_addr_str(addr).c_str());

	/* Create new path */
	auto& p = new_client_paths.emplace_back();
	p.wfd = move(wfd);
	p.remote_addr = addr;

	ep.add_fd(p.wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
			bind_front(&ctrl_ctx::on_client_path_fd, this, &p));
}


void ctrl_ctx::on_client_path_fd(client_path_t* path, int fd, uint32_t events)
{
	/* Ensure fd is correct */
	if (path->wfd.get_fd() != fd)
		throw runtime_error("Invalid path fd");

	bool disconnect = false;


	/* Send data */
	if (events & EPOLLOUT)
	{
		if (path->send_queue.size() > 0)
		{
			auto& elem = path->send_queue.front();

			auto ret = writev(fd, elem.iov, elem.iov_cnt);
			if (ret > 0)
			{
				while (ret > 0 && elem.iov_cnt > 0)
				{
					auto cnt = min((size_t) ret, elem.iov[0].iov_len);
					ret -= cnt;
					elem.iov[0].iov_len -= cnt;

					if (elem.iov[0].iov_len == 0)
					{
						elem.iov_cnt--;
						for (int i = 0; i < elem.iov_cnt; i++)
							elem.iov[i] = elem.iov[i+1];
					}
				}

				if (elem.iov_cnt == 0)
				{
					if (elem.cb_finished)
						elem.cb_finished();

					path->send_queue.pop();
				}
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Write error on path: %s; disconnecting\n",
						errno_str(errno).c_str());
				disconnect = true;
			}
		}

		if (path->send_queue.empty())
		{
			path->sender_enabled = false;
			ep.change_events(fd, EPOLLIN | EPOLLHUP | EPOLLRDHUP);
		}
	}


	/* Receive data */
	if (events & EPOLLIN)
	{
		if (path->rcv_req)
		{
			auto req = path->rcv_req;

			auto ret = read(fd, req->rcv_ptr, req->rcv_rem_size);
			if (ret > 0)
			{
				req->rcv_rem_size -= ret;
				req->rcv_ptr += ret;

				if (req->rcv_rem_size == 0)
				{
					/* TODO */
				}
			}
			else if (ret == 0)
			{
				disconnect = true;
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Read error on path: %s; disconnecting\n",
						errno_str(errno).c_str());
				disconnect = true;
			}
		}
		else
		{
			auto ret = read(
					fd,
					path->rcv_buf + path->rcv_buf_size,
					sizeof(path->rcv_buf) - path->rcv_buf_size);

			if (ret > 0)
			{
				path->rcv_buf_size += ret;

				/* Parse message header */
				while (path->rcv_buf_size >= 8)
				{
					auto msg_len = ser::read_u32(path->rcv_buf) + 4UL;
					auto msg_num = ser::read_u32(path->rcv_buf + 4);

					switch (msg_num)
					{
					default:
						if (msg_len > sizeof(path->rcv_buf))
						{
							fprintf(stderr, "Message from client too long; disconnecting\n");
							disconnect = true;
						}
						else if (path->rcv_buf_size >= msg_len)
						{
							if (parse_client_message_simple(
									path, path->rcv_buf + 8, msg_len - 8, msg_num))
							{
								disconnect = true;
							}

							path->rcv_buf_size -= msg_len;
							memmove(path->rcv_buf, path->rcv_buf + msg_len,
									path->rcv_buf_size);
						}
						break;
					};
				}
			}
			else if (ret == 0)
			{
				disconnect = true;
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Read error on path: %s; disconnecting\n",
						errno_str(errno).c_str());
				disconnect = true;
			}
		}
	}


	/* Disconnect if required */
	if (events & (EPOLLHUP | EPOLLRDHUP))
	{
		fprintf(stderr, "Path disconnected by remote\n");
		disconnect = true;
	}

	if (disconnect)
	{
		ep.remove_fd(fd);
		path->wfd.close();

		/* Put path on removal list */
		auto i = client_paths.begin();
		bool spliced = false;
		for (; i != client_paths.end(); i++)
		{
			if (&(*i) == path)
			{
				client_paths_to_remove.splice(
						client_paths_to_remove.end(), client_paths, i);
				spliced = true;
				break;
			}
		}

		if (!spliced)
		{
			for (i = new_client_paths.begin(); i != new_client_paths.end(); i++)
			{
				if (&(*i) == path)
				{
					client_paths_to_remove.splice(
							client_paths_to_remove.end(), new_client_paths, i);
					spliced = true;
					break;
				}
			}
		}

		if (!spliced)
			throw runtime_error("Failed to remove path");
	}
}


bool ctrl_ctx::parse_client_message_simple(client_path_t* p, const char* buf, size_t size, uint32_t msg_num)
{
	if (size < 8)
	{
		fprintf(stderr, "Invalid message size\n");
		return true;
	}

	auto seq = ser::sread_u64(buf);
	size -= 8;

	switch (msg_num)
	{
	case prot::client::REQ_CONNECT:
		return parse_client_message_connect(p, buf, size, seq);

	case prot::client::RESP_PROBE:
		return parse_client_message_resp_probe(p, buf, size, seq);

	case prot::client::REQ_GETATTR:
		return parse_client_message_getattr(p, buf, size, seq);

	case prot::client::REQ_READ:
		return parse_client_message_read(p, buf, size, seq);

	default:
		fprintf(stderr, "Unknown client message number %u\n", (unsigned) msg_num);
		return true;
	};
}

bool ctrl_ctx::parse_client_message_connect(client_path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 4)
	{
		fprintf(stderr, "Invalid CONNECT message size\n");
		return true;
	}

	auto client_id = ser::sread_u32(buf);

	if (client_id == 0)
	{
		/* New client */
		uint32_t new_id = 0;
		auto loop_det = next_client_id;
		for (;;)
		{
			auto tmp = next_client_id++;
			if (next_client_id == 0)
				next_client_id++;

			if (loop_det == next_client_id)
				break;

			bool taken = false;
			for (auto& c : clients)
			{
				if (c.client_id == tmp)
				{
					taken = true;
					break;
				}
			}

			if (!taken)
			{
				new_id = tmp;
				break;
			}
		}

		if (new_id == 0)
		{
			fprintf(stderr, "Client id space exhausted\n");
			return true;
		}

		/* Create new client */
		auto& c = clients.emplace_back();

		c.client_id = new_id;
		c.paths.push_back(p);
		p->client = &c;

		printf("New client %u\n", (unsigned) c.client_id);

		for (auto ip = new_client_paths.begin(); ip != new_client_paths.end(); ip++)
		{
			if (&(*ip) == p)
			{
				client_paths.splice(client_paths.end(), new_client_paths, ip);
				break;
			}
		}

		/* Respond with ACCEPT */
		char msg_buf[32];
		auto ptr = msg_buf;

		prot::serialize_hdr(ptr,
				16 + 4,
				prot::client::RESP_ACCEPT,
				seq);

		ser::swrite_u32(ptr, c.client_id);

		send_on_client_path_static(p, msg_buf, 20);
	}
	else
	{
		/* Existing client */
		/* Find client */
		client_t* c = nullptr;
		for (auto& cc : clients)
		{
			if (cc.client_id == client_id)
			{
				c = &cc;
				break;
			}
		}

		if (!c)
		{
			fprintf(stderr, "Denied new path for invalid client id %u\n",
					(unsigned) client_id);
			return true;
		}

		/* Add path to client */
		p->requires_probe = get_probe_token();
		for (auto p2 : c->paths)
		{
			if (p2->requires_probe || p2->wait_for_probe)
			{
				fprintf(stderr, "Protocol violation\n");
				return true;
			}

			p2->wait_for_probe = p->requires_probe;
		}

		p->client = c;
		c->paths.push_back(p);
		for (auto ip = new_client_paths.begin(); ip != new_client_paths.end(); ip++)
		{
			if (&(*ip) == p)
			{
				client_paths.splice(client_paths.end(), new_client_paths, ip);
				break;
			}
		}

		/* Send probe */
		char msg_buf[32];
		auto ptr = msg_buf;

		prot::serialize_hdr(ptr,
				16 + 8,
				prot::client::REQ_PROBE,
				get_request_id());

		ser::swrite_u64(ptr, p->requires_probe);

		send_on_client_path_static(p, msg_buf, 24);
	}

	return false;
}

bool ctrl_ctx::parse_client_message_resp_probe(
		client_path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 8)
	{
		fprintf(stderr, "Invalid RESP_PROBE message size\n");
		return true;
	}

	auto token = ser::sread_u64(buf);

	if (token == 0 || token != p->wait_for_probe || !p->client)
	{
		fprintf(stderr, "Protocol violation\n");
		return true;
	}

	p->wait_for_probe = 0;

	/* Check if all wait-for-probes have been processed and find path to be
	 * probed */
	client_path_t* pp = nullptr;

	for (auto p2 : p->client->paths)
	{
		if (p2->wait_for_probe != 0)
		{
			if (p2->wait_for_probe != token)
			{
				fprintf(stderr, "Protocol violation\n");
				return true;
			}

			return false;
		}

		if (p2->requires_probe != 0)
		{
			if (p2->requires_probe != token || pp)
			{
				fprintf(stderr, "Protocol violation\n");
				return true;
			}

			pp = p2;
		}
	}

	if (!pp)
		throw runtime_error("requires_probe path not found");

	/* All probes received, accept path */
	pp->requires_probe = 0;

	char msg_buf[32];
	auto ptr = msg_buf;

	prot::serialize_hdr(ptr,
			16 + 4,
			prot::client::RESP_ACCEPT,
			seq);

	ser::swrite_u32(ptr, pp->client->client_id);

	send_on_client_path_static(pp, msg_buf, 20);

	return false;
}

bool ctrl_ctx::parse_client_message_getattr(
		client_path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 0)
	{
		fprintf(stderr, "Invalid GETATTR message size\n");
		return true;
	}

	char msg_buf[32];
	auto ptr = msg_buf;

	prot::serialize_hdr(ptr,
			16 + 4 + 8,
			prot::client::RESP_GETATTR,
			seq);

	ser::swrite_i32(ptr, err::SUCCESS);
	ser::swrite_u64(ptr, data_map.size);

	send_on_client_path_static(p, msg_buf, 28);

	return false;
}

bool ctrl_ctx::parse_client_message_read(
		client_path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 16)
	{
		fprintf(stderr, "Invalid READ message size\n");
		return true;
	}

	auto ptr = buf;
	auto io_req = io_requests.emplace(io_requests.end());

	try
	{
		io_req->path = p;
		io_req->seq = seq;
		io_req->offset = ser::sread_u64(ptr);
		io_req->count = ser::sread_u64(ptr);

		/* Allocate a buffer */
		io_req->buf = fixed_buffer(io_req->count);

		memset(io_req->buf.ptr(), 0, io_req->count);

		/* Send response */
		char msg_buf[32];
		auto ptr = msg_buf;

		prot::serialize_hdr(ptr,
				16 + 4 + io_req->count,
				prot::client::RESP_READ,
				seq);

		ser::swrite_i32(ptr, err::SUCCESS);

		send_on_client_path_static(
				p,
				msg_buf, 20,
				io_req->buf.ptr(), io_req->count,
				bind_front(&ctrl_ctx::send_io_req_read_finished, this, io_req));
	}
	catch (...)
	{
		io_requests.erase(io_req);
		throw;
	}

	return false;
}


void ctrl_ctx::send_io_req_read_finished(list<io_request_t>::iterator i)
{
	io_requests.erase(i);
}


void ctrl_ctx::send_on_client_path_static(
		client_path_t* p,
		const char* buf, size_t size,
		const char* user_ptr, size_t user_size,
		cb_send_on_path_finished_t cb_finished)
{
	if (!p->wfd)
		return;

	if (size > SEND_STATIC_BUF_SIZE)
		throw invalid_argument("size too large for static sending");

	auto& elem = p->send_queue.emplace();
	memcpy(elem.static_buf, buf, size);

	elem.iov_cnt = 1;
	elem.iov[0].iov_base = elem.static_buf;
	elem.iov[0].iov_len = size;

	if (user_ptr)
	{
		elem.iov_cnt = 2;
		elem.iov[1].iov_base = (void*) user_ptr;
		elem.iov[1].iov_len = user_size;
	}

	elem.cb_finished = cb_finished;

	/* Enable sender if required */
	if (!p->sender_enabled)
	{
		ep.change_events(p->wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLOUT);
		p->sender_enabled = true;
	}
}


uint64_t ctrl_ctx::get_probe_token()
{
	/* NOTE: Actually, these tokens should be generated randomly */

	uint64_t token = 0;
	auto loop_det = next_probe_token;
	for (;;)
	{
		auto tmp = next_probe_token++;
		if (next_probe_token == 0)
			next_probe_token++;

		if (active_probe_tokens.find(tmp) == active_probe_tokens.end())
		{
			token = tmp;
			break;
		}

		if (next_probe_token == loop_det)
			break;
	}

	if (token == 0)
		throw runtime_error("Probe token space exhausted");

	active_probe_tokens.insert(token);
	return token;
}

void ctrl_ctx::free_probe_token(uint64_t token)
{
	auto i = active_probe_tokens.find(token);
	if (i == active_probe_tokens.end())
		throw runtime_error("Attempted to free already inactive probe token");

	active_probe_tokens.erase(i);
}


void ctrl_ctx::cleanup_clients()
{
	while (client_paths_to_remove.size())
	{
		auto& p = client_paths_to_remove.front();
		printf("Removing disconnected path from %s\n", in_addr_str(p.remote_addr).c_str());

		if (p.client)
		{
			for (auto i = p.client->paths.begin(); i != p.client->paths.end(); i++)
			{
				if (*i == &p)
				{
					p.client->paths.erase(i);
					break;
				}
			}

			if (p.client->paths.empty())
			{
				for (auto i = clients.begin(); i != clients.end(); i++)
				{
					if (&(*i) == p.client)
					{
						printf("Client %d has no paths; removing\n", p.client->client_id);
						clients.erase(i);
						break;
					}
				}
			}

			p.client = nullptr;
		}

		client_paths_to_remove.pop_front();
	}
}


void ctrl_ctx::on_dd_fd(ctrl_dd* dd, int fd, uint32_t events)
{
	if (fd != dd->get_fd())
		throw runtime_error("Got epoll event for invalid dd fd");

	bool disconnect = false;

	/* Send data */
	//if (events & EPOLLOUT)
	//{
	//	// auto prof = profiler_get("on_dd_fd(send)");

	//	bool disable_sender = false;
	//	if (dd->send_queue.size() > 0)
	//	{
	//		auto& qmsg = dd->send_queue.front();

	//		size_t to_write = min(
	//				2 * 1024UL * 1024,
	//				qmsg.msg_len - dd->send_msg_pos);

	//		auto ret = write(
	//				dd->get_fd(),
	//				qmsg.buf_ptr() + dd->send_msg_pos,
	//				to_write);

	//		if (ret >= 0)
	//		{
	//			dd->send_msg_pos += ret;
	//			if (dd->send_msg_pos == qmsg.msg_len)
	//			{
	//				qmsg.return_buffer(buf_pool_dd_io);
	//				dd->send_queue.pop();
	//				dd->send_msg_pos = 0;

	//				if (dd->send_queue.empty())
	//					disable_sender = true;
	//			}
	//		}
	//		else
	//		{
	//			disconnect = true;
	//		}
	//	}
	//	else
	//	{
	//		disable_sender = true;
	//	}

	//	if (disable_sender)
	//		ep.change_events(dd->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP);
	//}

	/* Read data */
	if (events & EPOLLIN)
	{
		// auto prof = profiler_get("on_dd_fd(recv)");

		const size_t read_chunk = 2 * 1024 * 1024ULL;

		if (!dd->rd_buf)
			dd->rd_buf = buf_pool_dd_io.get_buffer(dd->rd_buf_pos + read_chunk);
		else
			dd->rd_buf.ensure_size(dd->rd_buf_pos + read_chunk);

		auto ret = read(
				dd->get_fd(),
				dd->rd_buf.ptr() + dd->rd_buf_pos,
				read_chunk);

		if (ret > 0)
		{
			dd->rd_buf_pos += ret;

			/* Check if the message has been completely received */
			while (dd->rd_buf_pos >= 4)
			{
				size_t msg_len = ser::read_u32(dd->rd_buf.ptr());

				if (dd->rd_buf_pos >= msg_len + 4)
				{
					/* Move the message buffer out */
					dynamic_aligned_buffer msg_buf(move(dd->rd_buf));

					dd->rd_buf_pos -= msg_len + 4;
					dd->rd_buf = buf_pool_dd_io.get_buffer(dd->rd_buf_pos);
					memcpy(
							dd->rd_buf.ptr(),
							msg_buf.ptr() + (msg_len + 4),
							dd->rd_buf_pos);

					/* Process the message */
					if (process_dd_message(*dd, move(msg_buf), msg_len))
					{
						disconnect = true;
						break;
					}
				}
				else
				{
					break;
				}
			}
		}
		else
		{
			disconnect = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		disconnect = true;

	if (disconnect)
		throw runtime_error("Error reading data form dd.\n");
}

bool ctrl_ctx::process_dd_message(
		ctrl_dd& dd, dynamic_aligned_buffer&& _buf, size_t msg_len)
{
	buffer_pool_returner bp_ret(buf_pool_dd_io, move(_buf));
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::dd::reply::parse(bp_ret.buf.ptr() + 4, msg_len);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from dd: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
		case prot::dd::reply::READ:
			return process_dd_message(
					dd,
					static_cast<prot::dd::reply::read&>(*msg),
					move(bp_ret.buf));

		case prot::dd::reply::WRITE:
			return process_dd_message(
					dd,
					static_cast<prot::dd::reply::write&>(*msg));

		default:
			fprintf(stderr, "dd io: protocol violation\n");
			return true;
	}
}

bool ctrl_ctx::process_dd_message(ctrl_dd& dd, prot::dd::reply::read& msg, dynamic_aligned_buffer&& buf)
{
	/* Find request */
	auto i_req = dd.read_reqs.find(msg.request_id);
	if (i_req == dd.read_reqs.end())
	{
		fprintf(stderr, "dd io: received invalid request id\n");
		buf_pool_dd_io.return_buffer(move(buf));
		return true;
	}

	/* Complete request */
	auto req = move(i_req->second);
	dd.read_reqs.erase(i_req);

	req.result = msg.res;
	if (msg.data_length != req.size)
		req.result = err::IO;

	req.data = msg.data;
	req._buf = move(buf);

	auto cb = req.cb_completed;
	cb(move(req));

	return false;
}

bool ctrl_ctx::process_dd_message(ctrl_dd& dd, prot::dd::reply::write& msg)
{
	/* Find request */
	auto i_req = dd.write_reqs.find(msg.request_id);
	if (i_req == dd.write_reqs.end())
	{
		fprintf(stderr, "dd io: received invalid request id\n");
		return true;
	}

	/* Complete request */
	auto req = move(i_req->second);
	dd.write_reqs.erase(i_req);

	req.result = msg.res;

	auto cb = req.cb_completed;
	cb(move(req));

	return false;
}


bool ctrl_ctx::send_message_to_dd(ctrl_dd& dd, const prot::msg& msg,
		const char* data, size_t data_length)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr) + data_length);
	auto hdr_len = msg.serialize(buf.ptr());

	if (data_length > 0)
		memcpy(buf.ptr() + hdr_len, data, data_length);

	return send_message_to_dd(dd, move(buf), hdr_len + data_length);
}

bool ctrl_ctx::send_message_to_dd(ctrl_dd& dd,
		variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len)
{
	if (!dd.connected)
	{
		fprintf(stderr, "attempted to send message to disconnected dd\n");
		return true;
	}

	//auto was_empty = dd.send_queue.empty();
	//dd.send_queue.emplace(move(buf), msg_len);

	// if (was_empty)
	// 	ep.change_events(dd.get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


void ctrl_ctx::main()
{
	while (!quit_requested)
	{
		ep.process_events(-1);
		cleanup_clients();
	}
}


void ctrl_ctx::dd_read(dd_read_request_t&& req)
{
	auto& dd = *req.dd;

	prot::dd::req::read msg;
	msg.request_id = get_request_id();
	msg.offset = req.offset;
	msg.length = req.size;

	/* Register request */
	auto [i,created] = dd.read_reqs.emplace(msg.request_id, move(req));
	if (!created)
		throw runtime_error("dd io: request id conflict");

	/* Send message to dd */
	try
	{
		if (send_message_to_dd(dd, msg))
			throw runtime_error("failed to send message to dd\n");
	}
	catch (...)
	{
		/* Unregister request */
		dd.read_reqs.erase(i);
		throw;
	}
}

void ctrl_ctx::dd_write(dd_write_request_t&& req)
{
	auto& dd = *req.dd;

	prot::dd::req::write msg;
	msg.request_id = get_request_id();
	msg.offset = req.offset;
	msg.length = req.size;

	/* Register request */
	auto [i,created] = dd.write_reqs.emplace(msg.request_id, move(req));
	if (!created)
		throw runtime_error("dd io: request id conflict");

	/* Send message to dd */
	try
	{
		if (send_message_to_dd(dd, msg, req.data, req.size))
			throw runtime_error("failed to send message to dd\n");
	}
	catch (...)
	{
		/* Unregister request */
		dd.write_reqs.erase(i);
		throw;
	}
}
