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

#define DEBUG
#include "common/logging.h"

using namespace std;


worker_thread_base_t::~worker_thread_base_t()
{
}


void worker_thread_base_t::on_efd()
{
}

void worker_thread_base_t::msg(thread_msg_t&& msg)
{
	mb_sema_free.down();

	{
		unique_lock lk(m_mb_queue);
		mb_queue.emplace_back(move(msg));
	}

	mb_sema_avail.up();
	efd.signal();
}


send_thread_t::send_thread_t(ctrl_ctx& cctx)
	: cctx(cctx)
{
}


void send_thread_t::process_inbox()
{
	while (mb_sema_avail.try_down())
	{
		unique_lock lk(m_mb_queue);
		auto& msg = mb_queue.front();
		lk.unlock();

		/* Process IPC message */
		switch (msg.type)
		{
		case thread_msg_t::TYPE_QUIT:
			running = false;
			break;

		case thread_msg_t::TYPE_ADD_CLIENT_PATH:
			_add_client_path(msg.client_path);
			break;

		case thread_msg_t::TYPE_SEND:
			if (msg.client_path->send_thread_removed)
			{
				if (msg.sqe.iio_req)
					cctx.remove_io_request(*msg.sqe.iio_req);

				cctx.efd.signal();
			}
			else
			{
				msg.client_path->send_queue.emplace(move(msg.sqe));
				if (!msg.client_path->sender_enabled)
				{
					msg.client_path->sender_enabled = true;
					ep.change_events(msg.client_path->wfd.get_fd(),
							EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
				}
			}
			break;

		case thread_msg_t::TYPE_REMOVE_CLIENT_PATH:
			_remove_client_path(msg.client_path);
			msg.acknowledge();
			break;

		default:
			break;
		};

		lk.lock();
		mb_queue.pop_front();
		lk.unlock();

		mb_sema_free.up();
	}
}

void send_thread_t::_add_client_path(client_path_t* p)
{
	client_paths.push_back(p);

	ep.add_fd(p->wfd.get_fd(), EPOLLHUP | EPOLLRDHUP,
			bind_front(&send_thread_t::on_client_fd, this, p));
}

void send_thread_t::_remove_client_path(client_path_t* p)
{
	auto i = client_paths.begin();
	for (; i != client_paths.end(); i++)
	{
		if (*i == p)
			break;
	}

	if (i == client_paths.end())
		return;

	ep.remove_fd(p->wfd.get_fd());
	client_paths.erase(i);
	p->send_thread_removed = true;

	/* Clear send queue to release references of io requests to the path */
	while (p->send_queue.size())
	{
		auto& sqe = p->send_queue.front();
		if (sqe.iio_req)
		{
			cctx.remove_io_request(*sqe.iio_req);
			cctx.efd.signal();
		}

		p->send_queue.pop();
	}
}


void send_thread_t::on_client_fd(client_path_t* path, int fd, uint32_t events)
{
	bool error = events & (EPOLLHUP | EPOLLRDHUP);

	if (!error && (events & EPOLLOUT))
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
					elem.iov[0].iov_base = (char*) elem.iov[0].iov_base + cnt;

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

					if (elem.iio_req)
						cctx.remove_io_request(*elem.iio_req);

					path->send_queue.pop();
				}
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				error = true;
			}
		}

		if (path->send_queue.empty())
		{
			path->sender_enabled = false;
			ep.change_events(fd, EPOLLHUP | EPOLLRDHUP);
		}
	}

	if (error)
		_remove_client_path(path);
}


void send_thread_t::main()
{
	pthread_setname_np(pthread_self(), "sdfs-ctrl-send");

	debug("send thread %p started\n", this);

	while (running)
	{
		ep.process_events(-1);
		process_inbox();
	}

	debug("send thread %p stopped\n", this);
}


void send_thread_t::add_client_path(client_path_t* p)
{
	thread_msg_t m(thread_msg_t::TYPE_ADD_CLIENT_PATH);
	m.client_path = p;
	msg(move(m));
}


recv_thread_t::recv_thread_t(ctrl_ctx& cctx, vector<ctrl_dd*>&& dds)
	: cctx(cctx), dds(move(dds))
{
	/* Add dds to epoll instance */
	for (auto dd : this->dds)
	{
		ep.add_fd(dd->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&recv_thread_t::on_dd_fd_read, this, dd));
	}
}

recv_thread_t::~recv_thread_t()
{
	/* Remove dds from epoll instance */
	for (auto dd : dds)
		ep.remove_fd_ignore_unknown(dd->get_fd());
}


void recv_thread_t::process_inbox()
{
	while (mb_sema_avail.try_down())
	{
		unique_lock lk(m_mb_queue);
		auto& msg = mb_queue.front();
		lk.unlock();

		/* Process IPC message */
		switch (msg.type)
		{
		case thread_msg_t::TYPE_QUIT:
			running = false;
			break;

		default:
			break;
		};

		lk.lock();
		mb_queue.pop_front();
		lk.unlock();

		mb_sema_free.up();
	}
}


void recv_thread_t::on_dd_fd_read(ctrl_dd* dd, int fd, uint32_t events)
{
	if (fd != dd->get_fd())
		throw runtime_error("Got epoll event for invalid dd fd");

	bool disconnect = false;

	/* Read data */
	if (events & EPOLLIN)
	{
		if (dd->rcv_ext_ptr)
		{
			auto ret = read(dd->get_fd(), dd->rcv_ext_ptr, dd->rcv_ext_cnt);
			if (ret > 0)
			{
				dd->rcv_ext_ptr += ret;
				dd->rcv_ext_cnt -= ret;

				if (dd->rcv_ext_cnt == 0)
				{
					dd->rcv_ext_ptr = nullptr;
					cctx.complete_dd_read_request(dd);
				}
			}
			else
			{
				disconnect = true;
			}
		}
		else
		{
			auto ret = read(
					dd->get_fd(),
					dd->rcv_buf + dd->rcv_buf_size,
					sizeof(dd->rcv_buf) - dd->rcv_buf_size);

			if (ret > 0)
			{
				dd->rcv_buf_size += ret;
				bool handled = true;

				/* Parse message header */
				while (dd->rcv_buf_size >= 8 && handled)
				{
					auto msg_len = ser::read_u32(dd->rcv_buf) + 4UL;
					auto msg_num = ser::read_u32(dd->rcv_buf + 4);

					handled = false;

					switch (msg_num)
					{
					case prot::dd::reply::READ:
						if (dd->rcv_buf_size >= 12)
						{
							auto data_len = min(dd->rcv_buf_size - 8, msg_len - 8);
							if (cctx.parse_dd_message_read(
									dd, dd->rcv_buf + 8, msg_len - 8, data_len))
							{
								disconnect = true;
							}

							dd->rcv_buf_size -= data_len + 8;
							memmove(dd->rcv_buf, dd->rcv_buf + data_len + 8,
									dd->rcv_buf_size);

							handled = true;
						}
						break;

					default:
						if (msg_len > sizeof(dd->rcv_buf))
						{
							fprintf(stderr, "Message from dd too long; disconnecting\n");
							disconnect = true;
						}
						else if (dd->rcv_buf_size >= msg_len)
						{
							if (cctx.parse_dd_message_simple(
									dd, dd->rcv_buf + 8, msg_len - 8, msg_num))
							{
								disconnect = true;
							}

							dd->rcv_buf_size -= msg_len;
							memmove(dd->rcv_buf, dd->rcv_buf + msg_len,
									dd->rcv_buf_size);

							handled = true;
						}
						break;
					};
				}
			}
			else if (ret == 0)
			{
				fprintf(stderr, "dd %u disconnected.\n", (unsigned) dd->id);
				disconnect = true;
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Read error on connection to dd %u: %s; disconecting\n",
						(unsigned) dd->id, errno_str(errno).c_str());
				disconnect = true;
			}
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		disconnect = true;

	/* Cannot disconnect dd from recv thread yet, hence simply remove the epoll
	 * handler for now */
	if (disconnect)
		ep.remove_fd_ignore_unknown(fd);
}


void recv_thread_t::main()
{
	pthread_setname_np(pthread_self(), "sdfs-ctrl-recv");

	debug("recv thread %p started\n", this);

	while (running)
	{
		ep.process_events(-1);
		process_inbox();
	}

	debug("recv thread %p stopped\n", this);
}


ctrl_ctx::ctrl_ctx()
{
}

ctrl_ctx::~ctrl_ctx()
{
	/* Stop threads */
	for (auto& t : recv_threads)
		t.msg(thread_msg_t::TYPE_QUIT);

	for (auto& t : recv_thread_tobjs)
		t.join();


	for (auto& t : send_threads)
		t.msg(thread_msg_t::TYPE_QUIT);

	for (auto& t : send_thread_tobjs)
		t.join();


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

	ep.add_fd(wfd.get_fd(), EPOLLHUP | EPOLLRDHUP,
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

void ctrl_ctx::initialize_start_recv_threads()
{
	constexpr unsigned cnt_recv_threads = 4;

	/* Compute how dds will be distributed */
	auto dds_per_thread = (dds.size() + cnt_recv_threads - 1) / cnt_recv_threads;

	/* Recv threads */
	auto i_dd = dds.begin();
	for (unsigned i = 0; i < cnt_recv_threads; i++)
	{
		/* Distribute dds to threads */
		vector<ctrl_dd*> th_dds;
		for (unsigned j = 0; j < dds_per_thread && i_dd != dds.end(); j++, i_dd++)
			th_dds.push_back(&(*i_dd));

		/* Instantiate thread context */
		recv_threads.emplace_back(*this, move(th_dds));
		auto& rth = recv_threads.back();

		/* Start threads */
		try
		{
			recv_thread_tobjs.emplace_back(
					bind(&recv_thread_t::main, &rth));
		}
		catch (...)
		{
			recv_threads.pop_back();
			throw;
		}
	}
}

void ctrl_ctx::initialize_start_send_threads()
{
	constexpr unsigned cnt_send_threads = 4;

	/* Compute how dds will be distributed */
	auto dds_per_send_thread = (dds.size() + cnt_send_threads - 1) / cnt_send_threads;


	/* Send threads */
	auto i_dd = dds.begin();
	for (unsigned i = 0; i < cnt_send_threads; i++)
	{
		send_threads.emplace_back(*this);
		auto& sth = send_threads.back();

		/* Distribute dds to threads */
		for (unsigned j = 0; j < dds_per_send_thread && i_dd != dds.end(); j++, i_dd++)
			sth.dds.push_back(&(*i_dd));

		/* Start threads */
		try
		{
			send_thread_tobjs.emplace_back(
					bind(&send_thread_t::main, &send_threads.back()));
		}
		catch (...)
		{
			send_threads.pop_back();
			throw;
		}
	}
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

	/* Start threads */
	initialize_start_send_threads();
	initialize_start_recv_threads();
}


uint64_t ctrl_ctx::get_request_id()
{
	return next_request_id++;
}


list<io_request_t>::iterator ctrl_ctx::add_io_request()
{
	unique_lock lk(m_io_requests);
	io_requests.emplace(io_requests.end());
	return --io_requests.end();
}

void ctrl_ctx::remove_io_request(std::list<io_request_t>::iterator iio_req)
{
	unique_lock lk(m_io_requests);
	io_requests.erase(iio_req);
}


size_t ctrl_ctx::split_io(size_t offset, size_t size,
		dd_request_t* reqs, size_t max_req_count)
{
	auto ptr = offset;
	auto end_ptr = offset + size;

	size_t i;

	for (i = 0; i < max_req_count && ptr < end_ptr; i++)
	{
		auto chunk_size = min(data_map.block_size, end_ptr - ptr);

		/* Next full block */
		auto next_block = ((ptr + data_map.block_size) / data_map.block_size);
		chunk_size = min(chunk_size, next_block * data_map.block_size - ptr);

		auto block_num = ptr / data_map.block_size;

		/* Add chunk */
		reqs[i].offset =
			(block_num / data_map.dd_order.size()) * data_map.block_size
			+ ptr % data_map.block_size;

		reqs[i].size = chunk_size;
		reqs[i].dd = data_map.dd_order[block_num % data_map.dd_order.size()];
		reqs[i].data = (char*) (intptr_t) ptr - offset;

		ptr += chunk_size;
	}

	return i;
}


void ctrl_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		quit_requested = true;
}


void ctrl_ctx::on_efd()
{
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
	struct sockaddr_in6 addr{};
	socklen_t addrlen = sizeof(addr);

	WrappedFD wfd;
	wfd.set_errno(
			accept4(fd, (struct sockaddr*) &addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC),
			"accept");

	printf("New client-connection from %s\n", in_addr_str(addr).c_str());

	/* Create new path */
	auto& p = new_client_paths.emplace_back();
	p.wfd = move(wfd);
	p.remote_addr = addr;

	/* Reference count will >= 1 as long as new io_requests referencing the path
	 * can be created */
	p.ref_count.inc();

	ep.add_fd(p.wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
			bind_front(&ctrl_ctx::on_client_path_fd, this, &p));

	/* Assign path to send thread */
	static unsigned next_send_thread = 0;
	next_send_thread = (next_send_thread + 1) % send_threads.size();

	auto ith = send_threads.begin();
	for (unsigned i = 0; i < next_send_thread; i++, ith++);

	p.send_thread = &(*ith);
	ith->add_client_path(&p);
}


void ctrl_ctx::on_client_path_fd(client_path_t* path, int fd, uint32_t events)
{
	/* Ensure fd is correct */
	if (path->wfd.get_fd() != fd)
		throw runtime_error("Invalid path fd");

	bool disconnect = false;


	/* Receive data */
	if (events & EPOLLIN)
	{
		if (path->req)
		{
			auto req = path->req;

			auto ret = read(fd, req->rcv_ptr, req->rcv_rem_size);
			if (ret > 0)
			{
				req->rcv_rem_size -= ret;
				req->rcv_ptr += ret;

				if (req->rcv_rem_size == 0)
					complete_parse_client_write_request(path);
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
				bool handled = true;

				/* Parse message header */
				while (path->rcv_buf_size >= 8 && handled)
				{
					auto msg_len = ser::read_u32(path->rcv_buf) + 4UL;
					auto msg_num = ser::read_u32(path->rcv_buf + 4);

					handled = false;

					switch (msg_num)
					{
					case prot::client::REQ_WRITE:
						if (path->rcv_buf_size >= 24)
						{
							auto data_len = min(path->rcv_buf_size - 8, msg_len - 8);
							if (parse_client_message_write(
									path, path->rcv_buf + 8, msg_len - 8, data_len))
							{
								disconnect = true;
							}

							path->rcv_buf_size -= data_len + 8;
							memmove(path->rcv_buf, path->rcv_buf + data_len + 8,
									path->rcv_buf_size);

							handled = true;
						}
						break;

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

							handled = true;
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
		disconnect = true;

	if (disconnect)
	{
		ep.remove_fd(fd);

		/* No new io reqeusts can be created on this path now - hence decrement
		 * the reference count */
		path->ref_count.dec();

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

	debug("recv client message CONNECT from %u\n", (unsigned) client_id);

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
	auto iio_req = add_io_request();
	auto& io_req = *iio_req;

	try
	{
		io_req.ctrl_ptr = this;
		io_req.path = p;
		io_req.path_ref = p->ref_count;
		io_req.seq = seq;
		io_req.offset = ser::sread_u64(ptr);
		io_req.count = ser::sread_u64(ptr);

		/* Check that the request stays inside the data boundary, carries data,
		 * and is not larger than 32MiB */
		if (
				io_req.count == 0 ||
				io_req.count > 32 * 1024 * 1024 ||
				io_req.offset + io_req.count > data_map.size)
		{
			auto ptr = io_req.static_buf;
			prot::serialize_hdr(ptr,
					16 + 4,
					prot::client::RESP_READ,
					seq);

			ser::swrite_i32(ptr, err::IO);
			send_on_client_path_req(iio_req, io_req.static_buf, 20);

			return false;
		}

		/* Allocate a buffer */
		io_req.buf = fixed_buffer(io_req.count);

		/* Split request into chunks */
		io_req.cnt_dd_reqs = split_io(
				io_req.offset, io_req.count,
				io_req.dd_reqs.data(), io_req.dd_reqs.size());

		/* Perform dd IO */
		for (size_t i = 0; i < io_req.cnt_dd_reqs; i++)
		{
			auto& req = io_req.dd_reqs[i];

			req.data += (intptr_t) io_req.buf.ptr();

			/* Will be called from a different thread */
			req.cb_completed = ctrl_ctx::_dd_io_complete_client_read;

			/* In terms of C++, and typesafety, this is an awful hack; but it
			 * works... */
			static_assert(sizeof(iio_req) == sizeof(void*));
			memcpy((char*) &req.cb_arg, (char*) &iio_req, sizeof(void*));

			dd_req(&req);
		}
	}
	catch (...)
	{
		remove_io_request(iio_req);
		throw;
	}

	return false;
}

void ctrl_ctx::_dd_io_complete_client_read(void* arg)
{
	list<io_request_t>::iterator io_req;
	memcpy((char*) &io_req, (char*) &arg, sizeof(void*));

	auto ctrl_ptr = io_req->ctrl_ptr;
	ctrl_ptr->dd_io_complete_client_read(io_req);
}

void ctrl_ctx::dd_io_complete_client_read(list<io_request_t>::iterator io_req)
{
	auto cnt_completed = io_req->cnt_completed_dd_reqs.fetch_add(1, memory_order_acq_rel) + 1;

	/* Check if all requests have been completed */
	if (cnt_completed < io_req->cnt_dd_reqs)
		return;

	/* Check return status and potentially return error */
	for (size_t i = 0; i < io_req->cnt_dd_reqs; i++)
	{
		auto& r = io_req->dd_reqs[i];
		if (r.result != err::SUCCESS)
		{
			auto ptr = io_req->static_buf;
			prot::serialize_hdr(ptr,
					16 + 4,
					prot::client::RESP_READ,
					io_req->seq);

			ser::swrite_i32(ptr, r.result);
			send_on_client_path_req(io_req, io_req->static_buf, 20);
			return;
		}
	}

	/* Send data to the client */
	auto ptr = io_req->static_buf;

	prot::serialize_hdr(ptr,
			16 + 4 + io_req->count,
			prot::client::RESP_READ,
			io_req->seq);

	ser::swrite_i32(ptr, err::SUCCESS);

	send_on_client_path_req(io_req,
			io_req->static_buf, 20,
			io_req->buf.ptr(), io_req->count);
}


bool ctrl_ctx::parse_client_message_write(client_path_t* path,
		const char* ptr, size_t size, size_t data_len)
{
	if (size < 16)
	{
		fprintf(stderr, "Invalid WRITE message size\n");
		return true;
	}

	/* Allocate IO request */
	auto iio_req = add_io_request();
	auto& io_req = *iio_req;

	try
	{
		io_req.ctrl_ptr = this;
		io_req.path = path;
		io_req.path_ref = path->ref_count;
		io_req.seq = ser::sread_u64(ptr);
		io_req.offset = ser::sread_u64(ptr);

		size -= 16;
		data_len -= 16;
		io_req.count = size;

		/* Check that the request stays inside the data bounday, carries data,
		 * and is not larger than 32MiB */
		if (
				io_req.count == 0 ||
				io_req.count > 32 * 1024 * 1024 ||
				io_req.offset + io_req.count > data_map.size)
		{
			auto ptr = io_req.static_buf;
			prot::serialize_hdr(ptr,
					16 + 4,
					prot::client::RESP_WRITE,
					io_req.seq);

			ser::swrite_i32(ptr, err::IO);
			send_on_client_path_req(iio_req, io_req.static_buf, 20);

			return false;
		}

		/* Allocate buffer */
		io_req.buf = fixed_buffer(io_req.count);

		/* Copy data if any */
		if (data_len > 0)
			memcpy(io_req.buf.ptr(), ptr, data_len);

		/* Setup reading of remaining data if required, or complete reading
		 * request */
		path->req = &io_req;
		path->i_req = iio_req;

		if (size > data_len)
		{
			io_req.rcv_ptr = io_req.buf.ptr() + data_len;
			io_req.rcv_rem_size = size - data_len;
		}
		else
		{
			complete_parse_client_write_request(path);
		}
	}
	catch (...)
	{
		remove_io_request(iio_req);
		throw;
	}

	return false;
}

void ctrl_ctx::complete_parse_client_write_request(client_path_t* p)
{
	auto io_req = p->req;
	p->req = nullptr;

	/* Split request into chunks */
	io_req->cnt_dd_reqs = split_io(
			io_req->offset, io_req->count,
			io_req->dd_reqs.data(), io_req->dd_reqs.size());

	/* Perform dd IO */
	for (size_t i = 0; i < io_req->cnt_dd_reqs; i++)
	{
		auto& req = io_req->dd_reqs[i];

		req.data += (intptr_t) io_req->buf.ptr();
		req.dir_write = true;

		/* Will be called from a different thread */
		req.cb_completed = ctrl_ctx::_dd_io_complete_client_write;

		/* In terms of C++, and typesafety, this is another awful hack; but it
		 * works... */
		static_assert(sizeof(p->i_req) == sizeof(void*));
		memcpy((char*) &req.cb_arg, (char*) &p->i_req, sizeof(void*));

		dd_req(&req);
	}
}

void ctrl_ctx::_dd_io_complete_client_write(void* arg)
{
	list<io_request_t>::iterator io_req;
	memcpy((char*) &io_req, (char*) &arg, sizeof(void*));

	auto ctrl_ptr = io_req->ctrl_ptr;
	ctrl_ptr->dd_io_complete_client_write(io_req);
}

void ctrl_ctx::dd_io_complete_client_write(list<io_request_t>::iterator io_req)
{
	auto cnt_completed = io_req->cnt_completed_dd_reqs.fetch_add(1, memory_order_acq_rel) + 1;

	/* Check if all requests have been completed */
	if (cnt_completed < io_req->cnt_dd_reqs)
		return;

	/* Check return status */
	int res = err::SUCCESS;

	for (size_t i = 0; i < io_req->cnt_dd_reqs; i++)
	{
		auto& r = io_req->dd_reqs[i];
		if (r.result != err::SUCCESS)
		{
			res = r.result;
			break;
		}
	}

	/* Send response to the client */
	auto ptr = io_req->static_buf;
	prot::serialize_hdr(ptr,
			16 + 4,
			prot::client::RESP_WRITE,
			io_req->seq);

	ser::swrite_i32(ptr, res);
	send_on_client_path_req(io_req, io_req->static_buf, 20);
}


void ctrl_ctx::send_on_client_path_static(
		client_path_t* p, const char* buf, size_t size)
{
	thread_msg_t msg(thread_msg_t::TYPE_SEND);
	msg.client_path = p;

	msg.sqe.buf = (char*) malloc(size);
	if (!msg.sqe.buf)
		throw system_error(errno, generic_category());

	memcpy(msg.sqe.buf, buf, size);

	msg.sqe.iov_cnt = 1;
	msg.sqe.iov[0].iov_base = msg.sqe.buf;
	msg.sqe.iov[0].iov_len = size;

	p->send_thread->msg(move(msg));
}


void ctrl_ctx::send_on_client_path_req(
		list<io_request_t>::iterator iio_req,
		char* ptr1, size_t size1,
		char* ptr2, size_t size2)
{
	thread_msg_t msg(thread_msg_t::TYPE_SEND);
	msg.client_path = iio_req->path;

	msg.sqe.iio_req = iio_req;

	msg.sqe.iov_cnt = 1;
	msg.sqe.iov[0].iov_base = ptr1;
	msg.sqe.iov[0].iov_len = size1;

	if (ptr2 && size2)
	{
		msg.sqe.iov_cnt = 2;
		msg.sqe.iov[1].iov_base = ptr2;
		msg.sqe.iov[1].iov_len = size2;
	}

	iio_req->path->send_thread->msg(move(msg));
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
	for (auto ip = client_paths_to_remove.begin(); ip != client_paths_to_remove.end();)
	{
		auto& p = *ip;

		/* Don't remove a path as long as it is referenced */
		if (p.ref_count)
		{
			ip++;
			continue;
		}

		printf("Removing disconnected path from %s\n", in_addr_str(p.remote_addr).c_str());

		/* Remove the path from the sender thread */
		auto msg_sp = make_shared<sync_point>();

		thread_msg_t msg(thread_msg_t::TYPE_REMOVE_CLIENT_PATH);
		msg.client_path = &p;
		msg.sp = msg_sp;
		p.send_thread->msg(move(msg));

		msg_sp->wait();


		/* Remove path from client if the path is associated with a client; and
		 * remove the client if this was the client's last path */
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

		auto i_prev = ip++;
		client_paths_to_remove.erase(i_prev);
	}
}


void ctrl_ctx::on_dd_fd(ctrl_dd* dd, int fd, uint32_t events)
{
	if (fd != dd->get_fd())
		throw runtime_error("Got epoll event for invalid dd fd");

	bool disconnect = false;

	/* Send data */
	if (events & EPOLLOUT)
	{
		if (dd->send_queue.size() > 0)
		{
			auto& sqe = dd->send_queue.front();

			auto ret = writev(dd->get_fd(), sqe.iov, sqe.iov_cnt);
			if (ret > 0)
			{
				while (ret > 0 && sqe.iov_cnt > 0)
				{
					auto cnt = min((size_t) ret, sqe.iov[0].iov_len);
					ret -= cnt;
					sqe.iov[0].iov_len -= cnt;
					sqe.iov[0].iov_base = (char*) sqe.iov[0].iov_base + cnt;

					if (sqe.iov[0].iov_len == 0)
					{
						sqe.iov_cnt--;
						for (int i = 0; i < sqe.iov_cnt; i++)
							sqe.iov[i] = sqe.iov[i+1];
					}
				}

				if (sqe.iov_cnt == 0)
				{
					dd->send_queue.pop();
				}
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Write error on connection to dd %u: %s; disconecting\n",
						(unsigned) dd->id, errno_str(errno).c_str());
				disconnect = true;
			}
		}

		if (dd->send_queue.empty())
		{
			ep.change_events(dd->get_fd(), EPOLLHUP | EPOLLRDHUP);
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
	{
		fprintf(stderr, "dd %u disconnected.\n", (unsigned) dd->id);
		disconnect = true;
	}

	if (disconnect)
		throw runtime_error("Error reading data form dd.\n");
}

bool ctrl_ctx::parse_dd_message_simple(
		ctrl_dd* dd, const char* buf, size_t size, uint32_t msg_num)
{
	if (size < 8)
	{
		fprintf(stderr, "Invalid message size\n");
		return true;
	}

	switch (msg_num)
	{
	case prot::dd::reply::WRITE:
		return parse_dd_message_write(dd, buf, size);

	default:
		fprintf(stderr, "Unknown dd message number: %u\n", (unsigned) msg_num);
		return true;
	};
}

bool ctrl_ctx::parse_dd_message_read(
		ctrl_dd* dd, const char* ptr, size_t size, size_t data_len)
{
	if (size < 12)
	{
		fprintf(stderr, "dd io: Invalid READ reply\n");
		return true;
	}

	auto request_id = ser::sread_u64(ptr);
	auto result = ser::sread_i32(ptr);

	size -= 12;
	data_len -= 12;

	/* Find request */
	unique_lock lkr(dd->m_active_reqs);

	auto i_req = dd->active_reqs.find(request_id);
	if (i_req == dd->active_reqs.end())
	{
		fprintf(stderr, "dd io: Received invalid request id\n");
		return true;
	}

	auto req = i_req->second;
	req->result = result;

	lkr.unlock();

	/* Copy data if any */
	if (data_len > 0)
		memcpy(req->data, ptr, data_len);

	/* Setup read of remaining data if required, or complete request */
	dd->rcv_req = i_req;

	if (size > data_len)
	{
		dd->rcv_ext_ptr = req->data + data_len;
		dd->rcv_ext_cnt = size - data_len;
	}
	else
	{
		complete_dd_read_request(dd);
	}

	return false;
}

void ctrl_ctx::complete_dd_read_request(ctrl_dd* dd)
{
	unique_lock lkr(dd->m_active_reqs);

	auto req = dd->rcv_req->second;
	dd->active_reqs.erase(dd->rcv_req);
	dd->rcv_req = decltype(dd->active_reqs)::iterator();

	lkr.unlock();

	auto cb = req->cb_completed;
	auto arg = req->cb_arg;
	cb(arg);
}

bool ctrl_ctx::parse_dd_message_write(
		ctrl_dd* dd, const char* ptr, size_t size)
{
	if (size != 12)
	{
		fprintf(stderr, "dd io: Invalid WRITE reply\n");
		return true;
	}

	auto request_id = ser::sread_u64(ptr);
	auto result = ser::sread_i32(ptr);

	/* Find request */
	unique_lock lkr(dd->m_active_reqs);
	auto i_req = dd->active_reqs.find(request_id);
	if (i_req == dd->active_reqs.end())
	{
		fprintf(stderr, "dd io: Received invalid request id\n");
		return true;
	}

	/* Complete request */
	auto req = i_req->second;
	dd->active_reqs.erase(i_req);
	lkr.unlock();

	req->result = result;

	auto cb = req->cb_completed;
	auto arg = req->cb_arg;
	cb(arg);

	return false;
}


void ctrl_ctx::send_to_dd(
		ctrl_dd* dd, const char* static_buf, size_t static_size,
		const char* data, size_t data_size)
{
	auto was_empty = dd->send_queue.empty();
	dd->send_queue.emplace();
	auto& sqe = dd->send_queue.back();

	if (static_size > sizeof(sqe.static_buf))
		throw invalid_argument("static_size too large");

	memcpy(sqe.static_buf, static_buf, static_size);

	sqe.iov_cnt = 1;
	sqe.iov[0].iov_base = sqe.static_buf;
	sqe.iov[0].iov_len = static_size;

	if (data)
	{
		sqe.iov_cnt = 2;
		sqe.iov[1].iov_base = (void*) data;
		sqe.iov[1].iov_len = data_size;
	}

	if (was_empty)
		ep.change_events(dd->get_fd(), EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
}


void ctrl_ctx::main()
{
	while (!quit_requested)
	{
		ep.process_events(-1);
		cleanup_clients();
	}
}


void ctrl_ctx::dd_req(dd_request_t* req)
{
	auto dd = req->dd;

	if (req->dir_write)
	{
		prot::dd::req::write msg;
		msg.request_id = get_request_id();
		msg.offset = req->offset;
		msg.length = req->size;

		/* Register request */
		unique_lock lkr(dd->m_active_reqs);

		/* TODO: handle conflict */
		auto [i,created] = dd->active_reqs.emplace(msg.request_id, req);
		if (!created)
			throw runtime_error("dd io: request id conflict");

		/* Send message to dd */
		try
		{
			char buf[msg.serialize(nullptr)];
			auto len = msg.serialize(buf);

			send_to_dd(dd, buf, len, req->data, req->size);
		}
		catch (...)
		{
			/* Unregister request */
			dd->active_reqs.erase(i);
			throw;
		}
	}
	else
	{
		prot::dd::req::read msg;
		msg.request_id = get_request_id();
		msg.offset = req->offset;
		msg.length = req->size;

		/* Register request */
		unique_lock lkr(dd->m_active_reqs);

		/* TODO: handle conflict */
		auto [i,created] = dd->active_reqs.emplace(msg.request_id, req);
		if (!created)
			throw runtime_error("dd io: request id conflict");

		/* Send message to dd */
		try
		{
			char buf[msg.serialize(nullptr)];
			auto len = msg.serialize(buf);

			send_to_dd(dd, buf, len);
		}
		catch (...)
		{
			/* Unregister request */
			dd->active_reqs.erase(i);
			throw;
		}
	}
}
