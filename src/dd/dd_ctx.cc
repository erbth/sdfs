#include <algorithm>
#include "config.h"
#include "dd_ctx.h"
#include "common/dynamic_buffer.h"
#include "common/prot_dd_mgr.h"
#include "common/msg_utils.h"
#include "common/error_codes.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
}

using namespace std;


dd_ctx::dd_ctx(const string& device_file)
	: device_file(device_file)
{
}

dd_ctx::~dd_ctx()
{
	while (clients.size())
		remove_client(clients.begin());

	if (sock)
		epoll.remove_fd_ignore_unknown(sock.get_fd());
}

void dd_ctx::remove_client(decltype(clients)::iterator i)
{
	auto c = *i;

	c->invalid = true;
	epoll.remove_fd(c->get_fd());
	c->wfd.close();

	clients.erase(i);
}

void dd_ctx::remove_client(shared_ptr<dd_client> cptr)
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


void dd_ctx::initialize_sock()
{
	bool have_port = false;

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT
	};

	for (port = SDFS_DD_PORT_START; port <= SDFS_DD_PORT_END; port++)
	{
		sock.set_errno(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0), "socket");

		int reuseaddr = 1;
		check_syscall(
				setsockopt(sock.get_fd(), SOL_SOCKET, SO_REUSEADDR,
					&reuseaddr, sizeof(reuseaddr)),
				"setsockopt");

		addr.sin6_port = htons(port);

		if (bind(sock.get_fd(), (const sockaddr*) &addr, sizeof(addr)) < 0)
		{
			if (errno == EADDRINUSE)
				continue;
		}

		if (listen(sock.get_fd(), 5) < 0)
		{
			if (errno == EADDRINUSE)
				continue;

			throw system_error(errno, generic_category(), "listen");
		}

		have_port = true;
		break;
	}

	if (!have_port)
		throw runtime_error("Could not find a free port to listen on");

	epoll.add_fd(sock.get_fd(), EPOLLIN,
			bind(&dd_ctx::on_listen_sock, this, placeholders::_1, placeholders::_2));

	fprintf(stderr, "Listening on port %d\n", (int) port);
}

void dd_ctx::initialize_mgr()
{
	mgr_sock.set_errno(
			socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0),
			"socket(mgr)");

	/* Connect to mgr */
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};

	auto path_len = strlen(SDFS_DD_MGR_SOCKET_PATH) + 1;
	if (path_len > sizeof(addr.sun_path))
		throw runtime_error("unix socket path too long");

	memcpy(addr.sun_path, SDFS_DD_MGR_SOCKET_PATH, path_len);

	check_syscall(
			connect(mgr_sock.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"connect(mgr)");

	/* Send number and port */
	prot::dd_mgr_be::req::register_dd msg;
	msg.id = di.id;
	msg.port = port;

	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());

	check_syscall(
			write(mgr_sock.get_fd(), buf.ptr(), msg_len),
			"write(mgr)");

	/* Wait for response */
	auto ret_msg = receive_packet_msg<prot::dd_mgr_be::reply::parse>(mgr_sock.get_fd(), 5000);
	if (!ret_msg)
		throw runtime_error("Error while registering at dd-mgr");

	if (ret_msg->num != (unsigned) prot::dd_mgr_be::reply::msg_nums::REGISTER_DD)
		throw runtime_error("Invalid response while registering at dd-mgr");
}

void dd_ctx::initialize()
{
	/* Open device and read header */
	wfd.set_errno(open(device_file.c_str(), O_CLOEXEC | O_DIRECT | O_RDWR), "open");
	di = read_and_validate_device_header(wfd.get_fd());

	fprintf(stderr, "dd id: %u (gid: %s)\n", di.id, format_gid(di.gid).c_str());

	/* Find a free port and start listening */
	initialize_sock();

	/* Connect to sdfs-mgr and announce port */
	initialize_mgr();
}


void dd_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		quit_requested = true;
}

void dd_ctx::on_listen_sock(int fd, uint32_t events)
{
	WrappedFD wfd;
	wfd.set_errno(accept4(fd, nullptr, nullptr, SOCK_CLOEXEC), "accept");

	auto client = make_shared<dd_client>();
	client->wfd = move(wfd);

	epoll.add_fd(client->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
			bind_front(&dd_ctx::on_client_fd, this, client));

	clients.push_back(client);
}


void dd_ctx::on_client_fd(shared_ptr<dd_client> client, int fd, uint32_t events)
{
	if (fd != client->get_fd())
		throw runtime_error("Got epoll event for invalid client fd");

	bool rm_client = false;

	/* Send data */
	if (events & EPOLLOUT)
	{
		bool disable_sender = false;
		if (client->send_queue.size() > 0)
		{
			auto& qmsg = client->send_queue.front();

			size_t to_write = min(
					2 * 1024UL * 1024,
					qmsg.msg_len - client->send_msg_pos);

			auto ret = write(
					client->get_fd(),
					qmsg.buf_ptr() + client->send_msg_pos,
					to_write);

			if (ret >= 0)
			{
				client->send_msg_pos += ret;
				if (client->send_msg_pos == qmsg.msg_len)
				{
					qmsg.return_buffer(buf_pool_client);
					client->send_queue.pop();
					client->send_msg_pos = 0;

					if (client->send_queue.empty())
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
		const size_t read_chunk = 2 * 1024 * 1024ULL;

		if (!client->rd_buf)
			client->rd_buf = buf_pool_client.get_buffer(client->rd_buf_pos + read_chunk);
		else
			client->rd_buf.ensure_size(client->rd_buf_pos + read_chunk);

		auto ret = read(
				client->get_fd(),
				client->rd_buf.ptr() + client->rd_buf_pos,
				read_chunk);

		if (ret >= 0)
		{
			client->rd_buf_pos += ret;

			/* Check if the message has been completely received */
			while (client->rd_buf_pos >= 4)
			{
				size_t msg_len = ser::read_u32(client->rd_buf.ptr());

				if (client->rd_buf_pos >= msg_len + 4)
				{
					/* Move the message buffer out */
					dynamic_aligned_buffer msg_buf(move(client->rd_buf));

					client->rd_buf_pos -= msg_len + 4;
					client->rd_buf = buf_pool_client.get_buffer(client->rd_buf_pos);
					memcpy(
							client->rd_buf.ptr(),
							msg_buf.ptr() + (msg_len + 4),
							client->rd_buf_pos);

					/* Process the message */
					if (process_client_message(client, move(msg_buf), msg_len))
					{
						rm_client = true;
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
			rm_client = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		rm_client = true;

	if (rm_client)
		remove_client(client);
}

bool dd_ctx::process_client_message(shared_ptr<dd_client> client,
		dynamic_aligned_buffer&& buf, size_t msg_len)
{
	buffer_pool_returner bp_ret(buf_pool_client, move(buf));
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::dd::req::parse(bp_ret.buf.ptr() + 4, msg_len);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from client: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
		case prot::dd::req::GETATTR:
			return process_client_message(
					client,
					static_cast<prot::dd::req::getattr&>(*msg));

		case prot::dd::req::READ:
			return process_client_message(
					client,
					static_cast<prot::dd::req::read&>(*msg));

		case prot::dd::req::WRITE:
			return process_client_message(
					client,
					static_cast<prot::dd::req::write&>(*msg),
					move(bp_ret.buf));

		default:
			fprintf(stderr, "protocol violation\n");
			return true;
	}
}

bool dd_ctx::process_client_message(shared_ptr<dd_client> client,
		const prot::dd::req::getattr& msg)
{
	prot::dd::reply::getattr reply;

	reply.id = di.id;
	memcpy(reply.gid, di.gid, sizeof(di.gid));
	reply.size = di.usable_size();
	reply.raw_size = di.size;

	return send_message_to_client(client, reply);
}

/* READ */
bool dd_ctx::process_client_message(shared_ptr<dd_client> client,
		const prot::dd::req::read& msg)
{
	/* Check parameters */
	if (
			msg.length > MAX_IO_REQ_SIZE ||
			msg.length == 0 ||
			msg.offset + msg.length > di.usable_size())
	{
		return send_message_to_client(
				client,
				prot::dd::reply::read(msg.request_id, err::INVAL));
	}

	/* Submit IO */
	auto qe = get_free_io_queue_entry();
	if (!qe)
		throw runtime_error("IO queue full");

	qe->client = client;
	qe->client_request_id = msg.request_id;

	qe->offset = msg.offset;
	qe->length = msg.length;
	qe->req_offset = 0;
	qe->update_io_params();


	io_uring.queue_readv(wfd.get_fd(), &qe->iov, 1, qe->io_offset, 0,
			bind_front(&dd_ctx::on_read_io_finished, this, qe));

	io_uring.submit();

	return false;
}

void dd_ctx::on_read_io_finished(disk_io_req* qe, int res)
{
	if (res <= 0)
	{
		log_io_error(qe, -res);

		send_message_to_client(
				qe->client,
				prot::dd::reply::read(qe->client_request_id, err::IO));

		return_io_queue_entry(qe);
		return;
	}

	qe->req_offset += res;

	if (qe->req_offset < qe->io_length)
	{
		qe->update_io_params();

		io_uring.queue_readv(wfd.get_fd(), &qe->iov, 1,
				qe->io_offset + qe->req_offset, 0,
				bind_front(&dd_ctx::on_read_io_finished, this, qe));

		io_uring.submit();

		return;
	}


	/* Add message header */
	prot::dd::reply::read reply(qe->client_request_id, err::SUCCESS);
	reply.data_length = qe->length;
	int header_size = reply.serialize(nullptr);
	if (header_size > 4096)
		throw runtime_error("reply header too large");

	qe->base_for_send = qe->buf.ptr() + (4096 - header_size) + (qe->offset - qe->io_offset);
	qe->length_for_send = reply.serialize(qe->base_for_send) + qe->length;

	/* Return data to client */
	send_message_to_client(qe);
}


bool dd_ctx::process_client_message(shared_ptr<dd_client> client,
		const prot::dd::req::write& msg, dynamic_aligned_buffer&& buf)
{
	/* Check parameters */
	if (
			msg.length > MAX_IO_REQ_SIZE ||
			msg.length == 0 ||
			msg.offset + msg.length > di.usable_size())
	{
		buf_pool_client.return_buffer(move(buf));
		return send_message_to_client(
				client,
				prot::dd::reply::write(msg.request_id, err::INVAL));
	}

	/* If this is an unaligned write, read the corresponding region first */
	/* TODO: This requires a lock s.t. two parallel unaligned writes, which
	 * touch the same block, do not overwrite each other */
	auto qe = get_free_io_queue_entry();
	if (!qe)
		throw runtime_error("IO queue full");

	qe->client = client;
	qe->client_request_id = msg.request_id;
	qe->wr_buf = move(buf);
	qe->wr_base = msg.data;

	qe->offset = msg.offset;
	qe->length = msg.length;
	qe->req_offset = 0;
	qe->update_io_params();

	if (qe->io_offset != qe->offset || qe->io_length != qe->length)
	{
		/* Read the corresponding region */
		io_uring.queue_readv(wfd.get_fd(), &qe->iov, 1, qe->io_offset, 0,
				bind_front(&dd_ctx::on_write_read_finished, this, qe));

		io_uring.submit();
	}
	else
	{
		/* Directly write data */
		write_req_write(qe);
	}

	return false;
}

void dd_ctx::on_write_read_finished(disk_io_req* qe, int res)
{
	if (res <= 0)
	{
		log_io_error(qe, -res);

		send_message_to_client(
				qe->client,
				prot::dd::reply::write(qe->client_request_id, err::IO));

		buf_pool_client.return_buffer(move(qe->wr_buf));
		return_io_queue_entry(qe);
		return;
	}

	qe->req_offset += res;

	if (qe->req_offset < qe->io_length)
	{
		qe->update_io_params();

		io_uring.queue_readv(wfd.get_fd(), &qe->iov, 1,
				qe->io_offset + qe->req_offset, 0,
				bind_front(&dd_ctx::on_write_read_finished, this, qe));

		io_uring.submit();

		return;
	}

	/* Write data */
	qe->req_offset = 0;
	qe->update_io_params();
	write_req_write(qe);
}

void dd_ctx::write_req_write(disk_io_req* qe)
{
	/* Copy data into IO buffer */
	memcpy((char*) qe->iov.iov_base + (qe->offset - qe->io_offset), qe->wr_base, qe->length);
	qe->wr_base = nullptr;
	buf_pool_client.return_buffer(move(qe->wr_buf));

	/* Submit write */
	io_uring.queue_writev(wfd.get_fd(), &qe->iov, 1, qe->io_offset, 0,
			bind_front(&dd_ctx::on_write_io_finished, this, qe));

	io_uring.submit();
}

void dd_ctx::on_write_io_finished(disk_io_req* qe, int res)
{
	if (res <= 0)
	{
		log_io_error(qe, -res);

		send_message_to_client(
				qe->client,
				prot::dd::reply::write(qe->client_request_id, err::IO));

		return_io_queue_entry(qe);
		return;
	}

	qe->req_offset += res;
	if (qe->req_offset < qe->io_length)
	{
		qe->update_io_params();

		io_uring.queue_writev(wfd.get_fd(), &qe->iov, 1,
				qe->io_offset + qe->req_offset, 0,
				bind_front(&dd_ctx::on_write_io_finished, this, qe));

		io_uring.submit();

		return;
	}

	/* Notify client */
	send_message_to_client(
			qe->client,
			prot::dd::reply::write(qe->client_request_id, err::SUCCESS));

	return_io_queue_entry(qe);
}


bool dd_ctx::send_message_to_client(shared_ptr<dd_client> client, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message_to_client(client, move(buf), msg_len);
}

bool dd_ctx::send_message_to_client(shared_ptr<dd_client> client,
		variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len)
{
	if (client->invalid)
		return true;

	auto was_empty = client->send_queue.empty();

	if (holds_alternative<dynamic_buffer>(buf))
		client->send_queue.emplace(move(get<dynamic_buffer>(buf)), msg_len);
	else
		client->send_queue.emplace(move(get<dynamic_aligned_buffer>(buf)), msg_len);

	if (was_empty)
		epoll.change_events(client->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}

bool dd_ctx::send_message_to_client(disk_io_req* qe)
{
	auto client = qe->client;

	if (client->invalid)
		return true;

	auto was_empty = client->send_queue.empty();

	/* qe->req_offset is the negative header size */
	auto msg_len = qe->length_for_send;
	client->send_queue.emplace(move(qe), msg_len);

	if (was_empty)
		epoll.change_events(client->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


disk_io_req* dd_ctx::get_free_io_queue_entry()
{
	for (auto& qe : io_queue)
	{
		if (!qe.active)
		{
			qe.active = true;
			return &qe;
		}
	}

	return nullptr;
}

void dd_ctx::return_io_queue_entry(disk_io_req* qe)
{
	qe->offset = 0;
	qe->length = 0;
	qe->io_offset = 0;
	qe->io_length = 0;
	qe->req_offset = 0;
	qe->update_io_params();

	qe->client = nullptr;
	qe->client_request_id = 0;
	qe->base_for_send = nullptr;
	qe->length_for_send = 0;

	qe->wr_buf = dynamic_aligned_buffer();
	qe->wr_base = nullptr;

	qe->active = false;
}


void dd_ctx::on_epoll_ready(int res)
{
	if (res < 0)
		throw runtime_error("async poll on epoll fd failed");

	epoll.process_events(0);

	io_uring.submit_poll(epoll.get_fd(), POLLIN,
			bind_front(&dd_ctx::on_epoll_ready, this));
}


void dd_ctx::log_io_error(disk_io_req* qe, int code)
{
	char buf[1024];
	fprintf(stderr, "dd %u: IO error `%s' at offset %zu, size %zu\n",
			di.id, strerror_r(code, buf, sizeof(buf)),
			qe->io_offset, qe->io_length);
}


void dd_ctx::main()
{
	io_uring.submit_poll(epoll.get_fd(), POLLIN,
			bind_front(&dd_ctx::on_epoll_ready, this));

	while (!quit_requested)
		io_uring.process_requests(true);
}


const char* dd_queued_msg::buf_ptr()
{
	if (std::holds_alternative<dynamic_buffer>(vbuf))
		return std::get<dynamic_buffer>(vbuf).ptr();
	else if (std::holds_alternative<dynamic_aligned_buffer>(vbuf))
		return std::get<dynamic_aligned_buffer>(vbuf).ptr();
	else
		return std::get<disk_io_req*>(vbuf)->base_for_send;
}

dd_queued_msg::~dd_queued_msg()
{
	if (holds_alternative<disk_io_req*>(vbuf))
		dd_ctx::return_io_queue_entry(get<disk_io_req*>(vbuf));
}
