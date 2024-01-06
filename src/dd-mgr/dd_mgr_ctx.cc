#include "config.h"
#include "dd_mgr_ctx.h"
#include "common/serialization.h"
#include "common/utils.h"
#include "common/dynamic_buffer.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
}

using namespace std;


dd_mgr_client::dd_mgr_client(WrappedFD&& fd)
	: fd(move(fd))
{
}

int dd_mgr_client::get_fd()
{
	return fd.get_fd();
}


dd_mgr_ctx::~dd_mgr_ctx()
{
	for (auto& c : clients)
		epoll.remove_fd(c.get_fd());

	if (tfd)
		epoll.remove_fd_ignore_unknown(tfd.get_fd());

	if (ufd)
		epoll.remove_fd_ignore_unknown(ufd.get_fd());
}


void dd_mgr_ctx::initialize_unix_socket()
{
}

void dd_mgr_ctx::initialize_tcp()
{
	tfd.set_errno(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0), "socket(tcp)");

	int reuseaddr = 1;
	check_syscall(
			setsockopt(tfd.get_fd(), SOL_SOCKET, SO_REUSEADDR,
				&reuseaddr, sizeof(reuseaddr)),
			"setsockopt(tcp)");

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(SDFS_DD_MGR_PORT),
		.sin6_addr = IN6ADDR_ANY_INIT
	};

	check_syscall(
			bind(tfd.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
			"bind(tcp)");

	check_syscall(
			listen(tfd.get_fd(), 20),
			"listen(tcp)");

	epoll.add_fd(tfd.get_fd(), EPOLLIN,
			bind_front(&dd_mgr_ctx::on_client_conn, this));
}

void dd_mgr_ctx::initialize()
{
	initialize_unix_socket();
	initialize_tcp();
}


void dd_mgr_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		quit_requested = true;
}


void dd_mgr_ctx::on_client_conn(int fd, uint32_t events)
{
	auto cfd = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
	check_syscall(cfd, "accept4(tcp)");

	int fd_for_epoll = cfd;

	try
	{
		WrappedFD wfd;
		wfd = cfd;
		cfd = -1;

		clients.push_back(move(wfd));
	}
	catch (...)
	{
		if (cfd >= 0)
			close(cfd);
		throw;
	}

	try
	{
		epoll.add_fd(fd_for_epoll, EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&dd_mgr_ctx::on_client_fd, this));
	}
	catch (...)
	{
		clients.pop_back();
		throw;
	}
}

void dd_mgr_ctx::on_client_fd(int fd, uint32_t events)
{
	auto i = clients.begin();
	for (; i != clients.end(); i++)
	{
		if (i->get_fd() == fd)
			break;
	}

	if (i == clients.end())
		throw runtime_error("Got epoll event for invalid client fd");

	auto& c = *i;
	bool remove_client = false;

	if (events & EPOLLIN)
	{
		char rd_buf[2048];
		auto ret = read(c.get_fd(), rd_buf, sizeof(rd_buf));
		check_syscall(ret, "read(tcp)");

		if (ret >= 0)
		{
			if (c.read_buf_pos + ret <= sizeof(c.read_buf))
			{
				memcpy(c.read_buf + c.read_buf_pos, rd_buf, ret);
				c.read_buf_pos += ret;

				/* Check if the message has been completely received */
				if (c.read_buf_pos >= 4)
				{
					size_t msg_len = ser::read_u32(c.read_buf);

					if (c.read_buf_pos >= msg_len + 4)
					{
						/* Process the message */
						if (process_client_message(c, c.read_buf + 4, msg_len))
							remove_client = true;

						c.read_buf_pos -= msg_len + 4;
						memmove(c.read_buf, c.read_buf + msg_len + 4,
								c.read_buf_pos);
					}
				}
			}
			else
			{
				fprintf(stderr, "too long message via tcp; "
						"closing client connection\n");

				c.read_buf_pos = 0;
				remove_client = true;
			}
		}
		else
		{
			remove_client = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		remove_client = true;

	if (remove_client)
	{
		epoll.remove_fd(fd);
		clients.erase(i);
	}
}

bool dd_mgr_ctx::process_client_message(dd_mgr_client& c, const char* buf, size_t size)
{
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::dd_mgr_fe::req::parse(buf, size);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from client via tcp: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
	case (unsigned) prot::dd_mgr_fe::req::msg_nums::QUERY_DDS:
		return dd_mgr_ctx::process_client_message(c,
				static_cast<prot::dd_mgr_fe::req::query_dds&>(*msg));

	default:
		fprintf(stderr, "protocol violation via tcp\n");
		return true;
	}

	return false;
}

bool dd_mgr_ctx::process_client_message(
		dd_mgr_client& c, const prot::dd_mgr_fe::req::query_dds& msg)
{
	prot::dd_mgr_fe::reply::query_dds reply;

	/* TODO */

	return send_to_client(c, reply);
}

bool dd_mgr_ctx::send_to_client(dd_mgr_client& c, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto len = msg.serialize(buf.ptr());

	try
	{
		simple_write(c.get_fd(), buf.ptr(), len);
	}
	catch (const system_error&)
	{
		return true;
	}

	return false;
}


void dd_mgr_ctx::main()
{
	while (!quit_requested)
		epoll.process_events(-1);
}
