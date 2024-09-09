#include <cstdio>
#include <algorithm>
#include <regex>
#include <stdexcept>
#include "common/exceptions.h"
#include "common/serialization.h"
#include "common/error_codes.h"
#include "common/protocols.h"
#include "sdfs_ds_internal.h"
#include "config.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
}

using namespace std;


DSClient::DSClient(const vector<string>& srv_portals)
{
	unique_lock lk(m);

	try
	{
		init_paths(srv_portals);
		init_start_threads();
	}
	catch (...)
	{
		cleanup(lk);
		throw;
	}
}

DSClient::~DSClient()
{
	unique_lock lk(m);
	cleanup(lk);
}


void DSClient::init_paths(const vector<string>& srv_portals)
{
	unsigned path_id = 0;
	for (auto& pd : srv_portals)
	{
		auto& path = paths.emplace_back();
		path.srv_desc = pd;
		path.path_id = path_id++;

		if (regex_match(pd, regex(string("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"))))
		{
			path.addr.sin6_family = AF_INET6;
			path.addr.sin6_port = htons(SDFS_CTRL_PORT);

			if (inet_pton(AF_INET6, ("::FFFF:" + pd).c_str(),
						&path.addr.sin6_addr) != 1)
			{
				fprintf(stderr, "Failed to resolve portal address `%s': "
						"Invalid IPv4 address specification.\n", pd.c_str());
				continue;
			}

			WrappedFD wfd;
			wfd.set_errno(
					socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
					"socket");

			if (connect(wfd.get_fd(), (const struct sockaddr*) &path.addr, sizeof(path.addr)) < 0)
			{
				fprintf(stderr, "Failed to connect to portal `%s': %s.\n",
						pd.c_str(), errno_str(errno).c_str());
				continue;
			}

			path.wfd = move(wfd);
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

			auto gai_ret = getaddrinfo(pd.c_str(), nullptr, &hints, &addrs);
			if (gai_ret != 0)
			{
				fprintf(stderr, "Failed to resolve portal address `%s': %s\n",
						pd.c_str(), gai_error_str(gai_ret).c_str());
				continue;
			}

			path.addr.sin6_family = AF_INET6;
			path.addr.sin6_port = htons(SDFS_CTRL_PORT);

			try
			{
				for (struct addrinfo* ai = addrs; ai; ai = ai->ai_next)
				{
					WrappedFD wfd;
					wfd.set_errno(
							socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0),
							"socket");

					path.addr.sin6_addr = ((const struct sockaddr_in6*) ai->ai_addr)->sin6_addr;

					if (connect(wfd.get_fd(), (const struct sockaddr*) &path.addr, sizeof(path.addr)) == 0)
					{
						path.wfd = move(wfd);
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
	}

	print_path_status();
	if (paths.empty() || all_of(paths.begin(), paths.end(), [](auto& p){ return !p.wfd; }))
		throw runtime_error("No portal could be contacted");
}

void DSClient::init_start_threads()
{
	unsigned cnt_threads = paths.size();

	auto ipath = paths.begin();
	auto paths_per_thread = paths.size() / cnt_threads;

	for (unsigned i = 0; i < cnt_threads; i++)
	{
		auto& tctx = per_thread_ctx.emplace_back(i, &wt_quit);
		/* Build this vector before starting the threads s.t. it is not modified
		 * after the first thread has been started. This way, no synchronization
		 * is required to access it read-only from the threads (starting a
		 * threads contains a memory barrier) */
		wt_efds.push_back(&tctx.efd);
	}

	for (auto ictx = per_thread_ctx.begin(); ictx != per_thread_ctx.end(); ictx++)
	{
		auto& tctx = *ictx;
		auto inctx = ictx;

		if (++inctx != per_thread_ctx.end())
		{
			auto& next_tctx = *inctx;
			tctx.next_connect_paths = &next_tctx.connect_paths;
			tctx.next_efd = &next_tctx.efd;
		}

		tctx.ds_client = this;
		tctx.client_id = &client_id;
		tctx.next_seq = &next_seq;

		for (size_t j = 0; j < paths_per_thread && ipath != paths.end(); j++, ipath++)
		{
			tctx.paths.push_back(&(*ipath));
			path_order.push_back(&(*ipath));

			ipath->thread_efd = &tctx.efd;
		}

		worker_threads.emplace_back();

		try
		{
			worker_threads.back() = thread(bind(&worker_thread_ctx::main, &tctx));
		}
		catch (...)
		{
			worker_threads.pop_back();
			wt_efds.pop_back();
			per_thread_ctx.pop_back();
			throw;
		}
	}
}

void DSClient::cleanup(unique_lock<mutex>& lk)
{
	{
		unlocked ulk(lk);

		/* Signal threads */
		wt_quit.store(true, memory_order_release);
		wt_signal_all();

		/* Wait for worker threads */
		{
			for (auto& wt : worker_threads)
				wt.join();
		}
	}
}


/* Multipathing */
void DSClient::print_path_status()
{
	fprintf(stderr, "Path status:\n");
	for (auto& p : paths)
	{
		unique_lock lk(p.m_state_send);

		fprintf(stderr, "    %d: %s (addr.: %s): %s\n",
				p.path_id,
				p.srv_desc.c_str(), in_addr_str(p.addr).c_str(),
				p.wfd ? (p.accepted ? "connected" : "validating") : "unconnected");
	}

	fprintf(stderr, "\n");
}


std::pair<path_t*, std::unique_lock<std::mutex>> DSClient::choose_path(unsigned long seq)
{
	for (size_t offset = 0; offset < path_order.size(); offset++)
	{
		auto p = path_order[(seq + offset) % path_order.size()];
		unique_lock lkp(p->m_state_send);
		if (p->accepted)
			return {p, move(lkp)};
	}

	return {nullptr, unique_lock<mutex>()};
}

bool DSClient::schedule_io_request(unique_ptr<io_request_t>&& io_req)
{
	auto [p, lkp] = choose_path(io_req->seq);
	if (p)
	{
		/* Move to request map */
		auto p_req = io_req.get();
		/* Maybe TODO: handle conflict */
		auto [mi, inserted] = p->io_requests.emplace(p_req->seq, move(io_req));
		if (!inserted)
			throw runtime_error("seq number conflict");

		/* Schedule for sending */
		auto& entry = p->send_queue.emplace();

		if (p_req->static_buf_size)
		{
			memcpy(entry.static_buf, p_req->static_buf, p_req->static_buf_size);

			entry.iov[entry.iov_cnt].iov_base = entry.static_buf;
			entry.iov[entry.iov_cnt].iov_len = p_req->static_buf_size;
			entry.iov_cnt++;
		}

		if (p_req->send_data)
		{
			entry.iov[entry.iov_cnt].iov_base = p_req->data_ptr;
			entry.iov[entry.iov_cnt].iov_len = p_req->data_size;
			entry.iov_cnt++;
		}

		bool enable_sender = !p->sender_enabled;
		auto efd = p->thread_efd;
		lkp.unlock();

		if (enable_sender)
			efd->signal();

		return true;
	}

	return false;
}

void DSClient::schedule_pending_io_requests()
{
	unique_lock lk(m);

	while (io_req_queue.size())
	{
		if (!schedule_io_request(move(io_req_queue.front())))
			return;

		io_req_queue.pop();
	}
}


/* IO request queue */
void DSClient::submit_io_request(unique_ptr<io_request_t>&& io_req)
{
	unique_lock lk(m);

	/* Try to find an available path */
	if (schedule_io_request(move(io_req)))
		return;

	/* No path was available, put the request onto the queue */
	io_req_queue.push(move(io_req));
}


/* Worker threads */
void DSClient::wt_signal_all()
{
	for (auto efd : wt_efds)
		efd->signal();
}

void DSClient::wt_signal_all_except(unsigned thread_id)
{
	for (size_t i = 0; i < wt_efds.size(); i++)
	{
		if (i != thread_id)
			wt_efds[i]->signal();
	}
}

void worker_thread_ctx::on_eventfd()
{
	if (wt_quit->load(memory_order_release))
		stop_thread = true;

	/* Enable senders if required */
	for (auto& p : paths)
	{
		unique_lock lkp(p->m_state_send);
		if (p->wfd && !p->sender_enabled)
		{
			ep.change_events(p->wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLOUT);
			p->sender_enabled = true;
		}
	}

	/* Connect paths if required */
	if (connect_paths.load(memory_order_acquire))
	{
		connect_paths.store(false, memory_order_release);

		auto ip = paths.begin();
		for (; ip != paths.end() && (*ip)->accepted; ip++);

		if (ip != paths.end())
		{
			/* Send connect on first unconnected path */
			char buf[32];
			auto ptr = buf;

			prot::serialize_hdr(ptr,
					16 + 4,
					prot::client::REQ_CONNECT,
					next_seq->fetch_add(1, memory_order_acq_rel));

			ser::swrite_u32(ptr, client_id->load(memory_order_acquire));

			send_on_path_static(*ip, buf, 20);
		}
	}

	/* Reflect probe token if required */
	auto next_probe_round = ds_client->probe_round.load(memory_order_acquire);
	if (next_probe_round != completed_probe_round)
	{
		completed_probe_round = next_probe_round;

		char msg_buf[32];
		auto ptr = msg_buf;

		prot::serialize_hdr(ptr,
				16 + 8,
				prot::client::RESP_PROBE,
				ds_client->probe_seq);

		ser::swrite_u64(ptr, ds_client->probe_token);

		for (auto p : paths)
		{
			if (p->accepted)
				send_on_path_static(p, msg_buf, 24);
		}
	}
}


void worker_thread_ctx::on_path_fd(path_t* path, int fd, uint32_t events)
{
	/* Ensure fd is correct */
	if (path->wfd.get_fd() != fd)
		throw runtime_error("Invalid path fd");

	bool disconnect = false;


	/* Send data */
	if (events & EPOLLOUT)
	{
		unique_lock lk_mss(path->m_state_send);

		if (path->send_queue.size() > 0)
		{
			auto& elem = path->send_queue.front();
			lk_mss.unlock();

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

				lk_mss.lock();

				if (elem.iov_cnt == 0)
					path->send_queue.pop();
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				fprintf(stderr, "Write error on path %u: %s; disconnecting\n",
						(unsigned) path->path_id, errno_str(errno).c_str());
				disconnect = true;

				lk_mss.lock();
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
		if (path->rcv_req_ptr)
		{
			auto ret = read(fd, path->rcv_req_ptr, path->rcv_req_size);
			if (ret > 0)
			{
				path->rcv_req_size -= ret;
				path->rcv_req_ptr += ret;

				if (path->rcv_req_size == 0)
				{
					path->rcv_req_ptr = nullptr;
					if (finish_message_read(path))
						disconnect = true;
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
				bool handled = true;

				/* Parse message header */
				while (path->rcv_buf_size >= 8 && handled)
				{
					auto msg_len = ser::read_u32(path->rcv_buf) + 4UL;
					auto msg_num = ser::read_u32(path->rcv_buf + 4);

					handled = false;

					switch (msg_num)
					{
					case prot::client::RESP_READ:
						if (msg_len < 20)
						{
							fprintf(stderr, "Invalid READ reply size; disconnecting\n");
							disconnect = true;
							handled = true;
						}
						else if (path->rcv_buf_size >= 20)
						{
							auto to_remove = min(path->rcv_buf_size, msg_len);
							if (parse_message_read(
										path, path->rcv_buf + 8, to_remove,
										msg_len))
							{
								disconnect = true;
							}

							path->rcv_buf_size -= to_remove;
							memmove(path->rcv_buf, path->rcv_buf + to_remove,
									path->rcv_buf_size);

							handled = true;
						}
						break;

					default:
						if (msg_len > sizeof(path->rcv_buf))
						{
							fprintf(stderr, "Message from client too long; disconnecting\n");
							disconnect = true;
							handled = true;
						}
						else if (path->rcv_buf_size >= msg_len)
						{
							if (parse_message_simple(
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
	{
		//fprintf(stderr, "Path %u disconnected by remote\n",
		//		(unsigned) path->path_id);
		disconnect = true;
	}

	if (disconnect)
	{
		unique_lock lk_mss(path->m_state_send);

		ep.remove_fd(fd);

		path->accepted = false;
		path->wfd.close();

		path_status_changed = true;
	}
}


unique_ptr<io_request_t> worker_thread_ctx::remove_io_request(path_t* p, uint64_t seq)
{
	auto i = p->io_requests.find(seq);
	if (i == p->io_requests.end())
		return nullptr;

	auto io_req = move(i->second);
	p->io_requests.erase(i);

	return io_req;
}


void worker_thread_ctx::send_on_path_static(path_t* p, const char* buf, size_t size)
{
	unique_lock lk(p->m_state_send);

	if (!p->wfd)
		return;

	if (size > SEND_STATIC_BUF_SIZE)
		throw invalid_argument("size too large for static sending");

	auto& elem = p->send_queue.emplace();
	memcpy(elem.static_buf, buf, size);

	elem.iov_cnt = 1;
	elem.iov[0].iov_base = elem.static_buf;
	elem.iov[0].iov_len = size;

	/* Enable sender if required */
	if (!p->sender_enabled)
	{
		ep.change_events(p->wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLOUT);
		p->sender_enabled = true;
	}
}


bool worker_thread_ctx::parse_message_simple(
		path_t* p, const char* buf, size_t size, uint32_t msg_num)
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
	case prot::client::RESP_ACCEPT:
		return parse_message_accept(p, buf, size, seq);

	case prot::client::REQ_PROBE:
		return parse_message_req_probe(p, buf, size, seq);

	case prot::client::RESP_GETATTR:
		return parse_message_getattr(p, buf, size, seq);

	case prot::client::RESP_WRITE:
		return parse_message_write(p, buf, size, seq);

	default:
		fprintf(stderr, "Unknown message number %u\n", (unsigned) msg_num);
		return true;
	};
}

bool worker_thread_ctx::parse_message_accept(
		path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 4)
	{
		fprintf(stderr, "Invalid ACCEPT message size\n");
		return true;
	}

	auto msg_cid = ser::sread_u32(buf);
	auto cur_cid = client_id->load(memory_order_acquire);

	if (cur_cid == 0)
	{
		if (msg_cid == 0)
		{
			fprintf(stderr, "Received invalid client id from remote\n");
			return true;
		}

		fprintf(stderr, "Client id: %u\n", (unsigned) msg_cid);
		client_id->store(msg_cid, memory_order_release);
	}
	else
	{
		if (cur_cid != msg_cid)
		{
			fprintf(stderr, "Client id conflict\n");
			return true;
		}
	}

	//fprintf(stderr, "Path %u accepted by remote\n", (unsigned) p->path_id);
	{
		unique_lock lk_mss(p->m_state_send);
		p->accepted = true;
	}

	/* Send CONNECT on next path, if any */
	path_t* next_p = nullptr;
	for (auto i = paths.begin(); i != paths.end(); i++)
	{
		if (!(*i)->accepted)
		{
			next_p = *i;
			break;
		}
	}

	if (next_p)
	{
		char buf[32];
		auto ptr = buf;

		prot::serialize_hdr(ptr,
				16 + 4,
				prot::client::REQ_CONNECT,
				next_seq->fetch_add(1, memory_order_acq_rel));

		ser::swrite_u32(ptr, client_id->load(memory_order_acquire));

		send_on_path_static(next_p, buf, 20);
	}
	else
	{
		/* Notify next thread s.t. it connects its paths */
		if (next_efd)
		{
			next_connect_paths->store(true, memory_order_release);
			next_efd->signal();
		}
	}

	path_status_changed = true;

	return false;
}

bool worker_thread_ctx::parse_message_req_probe(
		path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 8)
	{
		fprintf(stderr, "Invalid REQUEST PROBE message size\n");
		return true;
	}

	auto token = ser::sread_u64(buf);

	/* Reflect probe to all active paths of this thread */
	char msg_buf[32];
	auto ptr = msg_buf;

	prot::serialize_hdr(ptr,
			16 + 8,
			prot::client::RESP_PROBE,
			seq);

	ser::swrite_u64(ptr, token);

	for (auto p2 : paths)
	{
		if (p2 != p && p2->accepted)
			send_on_path_static(p2, msg_buf, 24);
	}

	/* Instruct other threads to reflect the probe */
	ds_client->probe_token = token;
	ds_client->probe_seq = seq;
	completed_probe_round = ds_client->probe_round.fetch_add(1, memory_order_acq_rel) + 1;
	ds_client->wt_signal_all_except(thread_id);

	return false;
}

bool worker_thread_ctx::parse_message_getattr(
		path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 12)
	{
		fprintf(stderr, "Invalid GETATTR message size\n");
		return true;
	}

	auto io_req = remove_io_request(p, seq);
	if (!io_req)
		return true;

	auto res = ser::sread_i32(buf);

	auto attr = reinterpret_cast<sdfs::ds_attr_t*>(io_req->data_ptr);
	attr->size = ser::sread_u64(buf);

	io_req->cb_finished(seq, res, io_req->user_arg);

	return false;
}

bool worker_thread_ctx::parse_message_read(
		path_t* p, const char* buf, size_t buf_size, size_t size)
{
	size_t buffered_cnt = 0;

	/* buf_size >= 20 */

	auto seq = ser::sread_u64(buf);
	auto res = ser::sread_i32(buf);

	/* Find io request */
	unique_lock lk_mss(p->m_state_send);

	auto i_io_req = p->io_requests.find(seq);
	if (i_io_req == p->io_requests.end())
		return true;

	lk_mss.unlock();

	auto& io_req = i_io_req->second;

	if (buf_size > size)
		return true;

	if (res == err::SUCCESS)
	{
		if (size - 20 != io_req->data_size)
			return true;

		buffered_cnt = buf_size - 20;
		if (buffered_cnt > 0)
			memcpy(io_req->data_ptr, buf, buffered_cnt);
	}

	/* Handle errors */
	if (res != err::SUCCESS || buf_size == size)
	{
		auto _io_req = move(io_req);

		lk_mss.lock();
		p->io_requests.erase(i_io_req);
		lk_mss.unlock();

		_io_req->cb_finished(seq, res, _io_req->user_arg);
		return false;
	}

	/* Setup reading for the remaining data */
	lk_mss.lock();

	p->rcv_req = i_io_req;
	p->rcv_req_ptr = io_req->data_ptr + buffered_cnt;
	p->rcv_req_size = io_req->data_size - buffered_cnt;

	return false;
}

bool worker_thread_ctx::parse_message_write(
		path_t* p, const char* buf, size_t size, uint64_t seq)
{
	if (size != 4)
	{
		fprintf(stderr, "Invalid WRITE message size\n");
		return true;
	}

	auto io_req = remove_io_request(p, seq);
	if (!io_req)
		return true;

	auto res = ser::sread_i32(buf);

	io_req->cb_finished(seq, res, io_req->user_arg);

	return false;
}

bool worker_thread_ctx::finish_message_read(path_t* p)
{
	auto io_req = move(p->rcv_req->second);

	{
		unique_lock lk_mss(p->m_state_send);

		p->io_requests.erase(p->rcv_req);
	}

	io_req->cb_finished(io_req->seq, err::SUCCESS, io_req->user_arg);

	return false;
}


void worker_thread_ctx::main()
{
	pthread_setname_np(pthread_self(), "sdfs_ds_worker");

	/* Add paths to epoll instance */
	for (auto p : paths)
	{
		unique_lock lk(p->m_state_send);

		ep.add_fd(p->wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
				bind_front(&worker_thread_ctx::on_path_fd, this, p));
	}

	/* Send CONNECT on first path of first thread */
	if (thread_id == 0 && paths.size())
	{
		char buf[32];
		auto ptr = buf;

		prot::serialize_hdr(ptr,
				16 + 4,
				prot::client::REQ_CONNECT,
				next_seq->fetch_add(1, memory_order_acq_rel));

		ser::swrite_u32(ptr, client_id->load(memory_order_acquire));

		send_on_path_static(paths.front(), buf, 20);
	}

	while (!stop_thread)
	{
		ep.process_events(-1);

		if (path_status_changed)
		{
			/* Must be called without a lock; hence these function calles are
			 * done here */
			ds_client->schedule_pending_io_requests();
			ds_client->print_path_status();
			path_status_changed = false;
		}
	}
}


/* Public interface */
size_t DSClient::getattr(sdfs::ds_attr_t* dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto io_req = make_unique<io_request_t>();

	io_req->cb_finished = cb_finished;
	io_req->user_arg = arg;
	io_req->data_ptr = reinterpret_cast<char*>(dst);

	auto seq = next_seq.fetch_add(1, memory_order_acq_rel);
	io_req->seq = seq;

	/* Prepare message */
	auto ptr = io_req->static_buf;
	prot::serialize_hdr(ptr,
			16,
			prot::client::REQ_GETATTR,
			seq);

	io_req->static_buf_size = 16;

	/* Submit request */
	submit_io_request(move(io_req));

	return seq;
}

size_t DSClient::read(void* buf, size_t offset, size_t count,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto io_req = make_unique<io_request_t>();

	io_req->cb_finished = cb_finished;
	io_req->user_arg = arg;
	io_req->data_ptr = (char*) buf;
	io_req->offset = offset;
	io_req->data_size = count;

	auto seq = next_seq.fetch_add(1, memory_order_acq_rel);
	io_req->seq = seq;

	/* Prepare message */
	auto ptr = io_req->static_buf;
	prot::serialize_hdr(ptr,
			16 + 8 + 8,
			prot::client::REQ_READ,
			seq);

	ser::swrite_u64(ptr, io_req->offset);
	ser::swrite_u64(ptr, io_req->data_size);

	io_req->static_buf_size = 32;

	/* Submit request */
	submit_io_request(move(io_req));

	return seq;
}

size_t DSClient::write(const void* buf, size_t offset, size_t count,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto io_req = make_unique<io_request_t>();

	io_req->cb_finished = cb_finished;
	io_req->user_arg = arg;
	io_req->data_ptr = (char*) buf;
	io_req->offset = offset;
	io_req->data_size = count;

	auto seq = next_seq.fetch_add(1, memory_order_acq_rel);
	io_req->seq = seq;

	/* Prepare message */
	auto ptr = io_req->static_buf;
	prot::serialize_hdr(ptr,
			16 + 8 + count,
			prot::client::REQ_WRITE,
			seq);

	ser::swrite_u64(ptr, io_req->offset);

	io_req->static_buf_size = 24;
	io_req->send_data = true;

	/* Submit request */
	submit_io_request(move(io_req));

	return seq;
}
