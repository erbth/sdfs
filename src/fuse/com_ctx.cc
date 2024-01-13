#include <cstring>
#include <algorithm>
#include <regex>
#include "common/exceptions.h"
#include "common/serialization.h"
#include "com_ctx.h"
#include "config.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
}

using namespace std;


/* request management helpers */
request_t& find_req_for_reply(com_ctrl* ctrl, const prot::client::msg& msg)
{
	auto i = ctrl->reqs.find(msg.req_id);
	if (i == ctrl->reqs.end())
		throw runtime_error("got reply for unknown request");

	return i->second;
}

void finish_req(com_ctrl* ctrl, const request_t& req)
{
	if (ctrl->reqs.erase(req.id) != 1)
		throw runtime_error("attempted to finish non-existent request");
}

/* req will be copied */
void add_req(com_ctrl* ctrl, const request_t& req)
{
	auto [i,ins] = ctrl->reqs.insert({req.id, req});
	if (!ins)
		throw runtime_error("request id conflict");
}

/* com_ctx */
com_ctx::com_ctx()
{
}

com_ctx::~com_ctx()
{
	{
		unique_lock lk(m);
		evfd.signal();
	}

	worker_thread.join();
	unique_lock lk(m);

	while (ctrls.size() > 0)
		remove_controller(ctrls.begin());
}


void com_ctx::initialize_cfg()
{
	cfg = read_sdfs_config_file();
}

void com_ctx::initialize_connect()
{
	/* Connect to controllers */
	for (auto& desc : cfg.controllers)
	{
		com_ctrl c;
		c.id = desc.id;

		/* Resolve address */
		if (regex_match(desc.addr_str, regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")))
		{
			struct sockaddr_in6 addr = {
				.sin6_family = AF_INET6,
				.sin6_port = htons(SDFS_CTRL_PORT)
			};

			if (inet_pton(AF_INET6, ("::FFFF:" + desc.addr_str).c_str(),
						&addr.sin6_addr) != 1)
			{
				throw runtime_error("Failed to resolve controller address `" +
						desc.addr_str + "'");
			}

			c.wfd.set_errno(
					socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
					"socket");

			check_syscall(
					connect(c.get_fd(), (const struct sockaddr*) &addr, sizeof(addr)),
					("connect to controller `" + desc.addr_str + "'").c_str());
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

			auto gai_ret = getaddrinfo(desc.addr_str.c_str(),
					nullptr, &hints, &addrs);

			if (gai_ret != 0)
			{
				throw gai_exception(gai_ret,
						"Failed to resolve controller address `" +
						desc.addr_str + "': ");
			}

			struct sockaddr_in6 addr = {
				.sin6_family = AF_INET6,
				.sin6_port = htons(SDFS_CTRL_PORT)
			};

			bool connected = false;

			try
			{
				for (struct addrinfo* ai = addrs; ai; ai = ai->ai_next)
				{
					c.wfd.set_errno(
							socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
							"socket");

					addr.sin6_addr = ((const struct sockaddr_in6&) ai->ai_addr).sin6_addr;

					auto ret = connect(c.get_fd(), (const struct sockaddr*) &addr, sizeof(addr));
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
			{
				throw runtime_error("Failed to connect to controller `" +
						desc.addr_str + "'");
			}
		}

		ctrls.push_back(move(c));

		try
		{
			epoll.add_fd(ctrls.back().get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
					bind_front(&com_ctx::on_ctrl_fd, this, &ctrls.back()));
		}
		catch (...)
		{
			ctrls.pop_back();
			throw;
		}

		printf("Connected to controller %u (%s)\n",
				ctrls.back().id, desc.addr_str.c_str());
	}
}

void com_ctx::initialize()
{
	unique_lock lk(m);

	initialize_cfg();
	initialize_connect();
}

void com_ctx::start_threads()
{
	worker_thread = thread(bind_front(&com_ctx::worker_thread_func, this));
}


void com_ctx::worker_thread_func()
{
	while (!quit_requested.load(memory_order_acquire))
		epoll.process_events(-1);
}


void com_ctx::remove_controller(decltype(ctrls)::iterator i)
{
	printf("Disconnected from controller %u\n", i->id);

	auto& c = *i;

	if (c.wfd)
		epoll.remove_fd(c.get_fd());

	ctrls.erase(i);
}

void com_ctx::remove_controller(com_ctrl* cptr)
{
	auto i = ctrls.begin();
	for (; i != ctrls.end(); i++)
	{
		if (&(*i) == cptr)
			break;
	}

	if (i == ctrls.end())
		throw invalid_argument("No such controller in controller list");

	remove_controller(i);
}


void com_ctx::on_evfd()
{
	quit_requested.store(true, memory_order_release);
}

void com_ctx::on_ctrl_fd(com_ctrl* ctrl, int fd, uint32_t events)
{
	if (fd != ctrl->get_fd())
		throw runtime_error("Got epoll event for invalid fd");

	bool rm_ctrl = false;

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
				rm_ctrl = true;
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
		const size_t read_chunk = 100 * 1024;
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
					if (process_message(ctrl, move(msg_buf), msg_len))
						rm_ctrl = true;
				}
			}
		}
		else
		{
			rm_ctrl = true;
		}
	}

	if (events & (EPOLLHUP | EPOLLRDHUP))
		rm_ctrl = true;

	if (rm_ctrl)
		remove_controller(ctrl);
}


bool com_ctx::process_message(
		com_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len)
{
	unique_ptr<prot::msg> msg;

	try
	{
		msg = prot::client::reply::parse(buf.ptr() + 4, msg_len);
	}
	catch (const prot::exception& e)
	{
		fprintf(stderr, "Invalid message from controller: %s\n", e.what());
		return true;
	}

	switch (msg->num)
	{
		case prot::client::reply::GETATTR:
			return process_message(
					ctrl,
					static_cast<prot::client::reply::getattr&>(*msg));

		default:
			fprintf(stderr, "protocol violation\n");
			return true;
	}
}

bool com_ctx::process_message(com_ctrl* ctrl, prot::client::reply::getattr& msg)
{
	/* Find corresponding request */
	auto& req = find_req_for_reply(ctrl, msg);

	req_getattr_result res = {
		.size_total = msg.size_total,
		.size_used = msg.size_used,
		.inodes_total = msg.inodes_total,
		.inodes_used = msg.inodes_used
	};

	req.cb_getattr(res);

	finish_req(ctrl, req);

	return false;
}


bool com_ctx::send_message(com_ctrl* ctrl, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message(ctrl, move(buf), msg_len);
}

bool com_ctx::send_message(com_ctrl* ctrl, dynamic_buffer&& buf, size_t msg_len)
{
	auto was_empty = ctrl->send_queue.empty();
	ctrl->send_queue.emplace(move(buf), msg_len);

	if (was_empty)
		epoll.change_events(ctrl->get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


com_ctrl* com_ctx::choose_ctrl()
{
	if (ctrls.size() == 0)
		throw runtime_error("No controllers available");

	/* There should be less-enough controller s.t. walking the list is not
	 * harmful. */
	auto t = next_ctrl++ % ctrls.size();
	unsigned i = 0;
	for (auto ic = ctrls.begin();; i++, ic++)
	{
		if (i == t)
			return &(*ic);
	}
}


void com_ctx::request_getattr(req_cb_getattr_t cb)
{
	unique_lock lk(m);

	request_t req{};
	req.cb_getattr = cb;

	prot::client::req::getattr msg;
	msg.req_id = req.id;

	auto ctrl = choose_ctrl();
	add_req(ctrl, req);
	send_message(ctrl, msg);
}
