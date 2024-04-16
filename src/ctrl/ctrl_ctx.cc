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

bool inode::enough_space_for_file(const std::string& name) const
{
	size_t entry_size = 0;
	for (const auto& [f_name, f_node_id, f_type] : files)
		entry_size += 1 + f_name.size() + 8 + 1;

	entry_size += 1 + name.size() + 8 + 1;

	return entry_size <= 3480;
}

void inode::serialize(char* buf) const
{
	memset(buf, 0, 4096);
	auto ptr = buf;

	ser::swrite_u8(ptr, type);

	/* For extension-inodes */
	ser::swrite_u64(ptr, 0);

	if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		ser::swrite_u64(ptr, nlink);
		ser::swrite_u64(ptr, size);
		ser::swrite_u64(ptr, mtime);

		/* 1+8+3*8 = 33; reserve first 256 bytes */
		ptr = buf + 256;

		if (type == TYPE_FILE)
		{
			if (allocations.size() > 240)
				throw invalid_argument("at most 240 allocations per inode are supported");

			for (const auto& a : allocations)
			{
				ser::swrite_u64(ptr, a.offset);
				ser::swrite_u64(ptr, a.size);
			}
		}
		else
		{
			size_t entry_size = 0;
			for (const auto& [name, f_node_id, f_type] : files)
			{
				if (name.size() > 255 || name.size() == 0)
					throw invalid_argument("filename too long or empty");

				if (f_node_id == 0)
					throw invalid_argument("dir entry node_id is 0");

				entry_size += 1 + name.size() + 8 + 1;

				if (entry_size > 3480)
					throw invalid_argument("file reference data structure too large");

				ser::swrite_u8(ptr, name.size());
				memcpy(ptr, name.c_str(), name.size());
				ptr += name.size();
				ser::swrite_u64(ptr, f_node_id);
				ser::swrite_u8(ptr, f_type);
			}
		}
	}
}

void inode::parse(const char* buf)
{
	auto ptr = buf;
	type = (inode::inode_type) ser::sread_u8(ptr);

	/* For extension-inodes */
	ser::sread_u64(ptr);

	if (type == TYPE_FREE)
	{
	}
	else if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		nlink = ser::sread_u64(ptr);
		size = ser::sread_u64(ptr);
		mtime = ser::sread_u64(ptr);

		ptr = buf + 256;

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
				char buf[256];
				uint8_t namesz = ser::sread_u8(ptr);
				if (namesz == 0)
					break;

				memcpy(buf, ptr, namesz);
				ptr += namesz;

				buf[min(namesz, (uint8_t) 255)] = '\0';

				auto f_node_id = ser::sread_u64(ptr);
				if (f_node_id == 0)
					break;

				auto f_type = ser::sread_u8(ptr);

				files.emplace_back(string(buf, namesz), f_node_id, f_type);
			}
		}
	}
	else
	{
		throw invalid_argument("Invalid inode type: `" + to_string(type) + "'");
	}
}

ctrl_ctx::ctrl_ctx()
{
}

ctrl_ctx::~ctrl_ctx()
{
	if (client_lfd)
		epoll.remove_fd_ignore_unknown(client_lfd.get_fd());

	while (clients.size() > 0)
		remove_client(clients.begin());

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
	auto reply = receive_stream_msg<
		prot::dd_mgr_fe::reply::parse,
		(unsigned) prot::dd_mgr_fe::reply::msg_nums::QUERY_DDS
			>(wfd.get_fd(), 30000);

	for (const auto& desc : static_cast<prot::dd_mgr_fe::reply::query_dds&>(*reply).dds)
	{
		for (auto& dd : dds)
		{
			if (dd.id == desc.id)
			{
				if (desc.port < SDFS_DD_PORT_START || desc.port > SDFS_DD_PORT_END)
					throw runtime_error("Received invalid dd port");

				if (dd.wfd)
				{
					printf("  ignoring duplicate dd: %u\n", dd.id);
					continue;
				}

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
			(wfd.get_fd(), 30000);

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

	/* populate ctrl_dd structure */
	dd.size = reply.size;
	printf("    size: %s (%lu B), raw size: %s (%lu B)\n",
			format_size_bin(reply.size).c_str(), (long unsigned) reply.size,
			format_size_bin(reply.raw_size).c_str(), (long unsigned) reply.raw_size);

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

	epoll.add_fd(client_lfd.get_fd(),
			EPOLLIN, bind_front(&ctrl_ctx::on_client_lfd, this));
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
	initialize_root_directory();

	/* Create listening sockets */
	initialize_client_listener();
}


void ctrl_ctx::build_data_map()
{
	auto& dmap = data_map;

	dmap.n_dd = dds.size();
	dmap.stripe_size = dmap.block_size * dmap.n_dd;

	/* Minimum dd size */
	size_t min_dd_size = numeric_limits<size_t>::max();
	for (const auto& dd: dds)
		min_dd_size = min(min_dd_size, dd.size);

	/* Choose inode directory size */
	size_t div_fct = (min_dd_size / 4096) > 1000000 ? 100 : 10;

	dmap.inode_directory_size = (min_dd_size / div_fct) & ~(1024ULL * 1024 - 1);
	dmap.total_inode_count = (dmap.inode_directory_size * 8) / (4096*8 + 1);

	/* Safety check */
	if (dmap.total_inode_count * 4096 + (dmap.total_inode_count + 7) / 8 > dmap.inode_directory_size)
		throw runtime_error("error while computing inode directory size");

	/* For simplicity, the root inode is always empty (sentinal value) */
	if (dmap.total_inode_count < 2)
		throw runtime_error("inode directory too small");

	printf("Inode directory size: %lu (%s)\n",
			(long unsigned) dmap.total_inode_count,
			format_size_bin(dmap.inode_directory_size).c_str());


	/* Calculate available data size */
	size_t s_dd = (min_dd_size - dmap.inode_directory_size) &
		~(1024ULL * 1024 - 1);

	double c_bdd = s_dd / (dmap.allocation_granularity + dmap.n_dd / 8.);
	size_t c_blocks = (size_t) floor(c_bdd * dmap.n_dd);
	dmap.allocation_bitmap_size =
		((c_blocks + 7) / 8 + (1024*1024 - 1)) & ~(1024ULL * 1024 - 1);

	if (s_dd <= dmap.allocation_bitmap_size)
		throw runtime_error("total data size would be negative or zero");

	dmap.total_data_size = ((s_dd - dmap.allocation_bitmap_size) & ~(1024ULL * 1024 - 1)) * dmap.n_dd;

	printf("Total data size: %s (allocation bitmap size: %s)\n",
			format_size_bin(dmap.total_data_size).c_str(),
			format_size_bin(dmap.allocation_bitmap_size).c_str());


	/* Calculate dd position offsets */
	for (auto& dd : dds)
	{
		dd.inode_directory_offset = (dd.size - dmap.inode_directory_size) & ~(1024ULL * 1024 - 1);
		dd.inode_bitmap_offset = dd.inode_directory_offset + dmap.total_inode_count * 4096;

		dd.allocation_bitmap_offset = dd.inode_directory_offset - dmap.allocation_bitmap_size;

		/* Safety check */
		if (dd.allocation_bitmap_offset < (dmap.total_data_size + dmap.n_dd - 1) / dmap.n_dd)
			throw runtime_error("error while computing available data size");
	}


	/* Build dd RR order */
	for (auto& dd : dds)
		dmap.dd_rr_order.push_back(&dd);

	sort(dmap.dd_rr_order.begin(), dmap.dd_rr_order.end(), [](auto a, auto b) {
			return a->id < b->id;
	});
}


void ctrl_ctx::initialize_inode_directory()
{
	size_t alloc_size = (data_map.total_inode_count + 7) / 8;
	if (alloc_size > 100 * 1024 * 1024ULL)
		throw runtime_error("Inode directory allocator too large");

	alloc_size = (alloc_size + 4095) & ~(4095ULL);

	inode_directory._allocator_buffer = fixed_aligned_buffer(4096, alloc_size);
	inode_directory.allocator_bitmap = (uint8_t*) inode_directory._allocator_buffer.ptr();

	memset(inode_directory.allocator_bitmap, 0, alloc_size);

	/* Read inode allocation bitmap from first dd if valid */
	/* TODO */

	/* Initialize allocated inode count */
	inode_directory.allocated_count = 0;
	for (size_t i = 0; i < data_map.total_inode_count; i++)
	{
		auto off = i / 8;
		auto mask = 1 << (i % 8);

		if (inode_directory.allocator_bitmap[off] & mask)
			inode_directory.allocated_count++;
	}
}

void ctrl_ctx::initialize_root_directory()
{
	/* Try to load the root directory and create one if it does not yet exist.
	 * */

	if (true)
	{
		printf("The root directory does not exist, creating a new one\n");

		auto n = make_shared<inode>();

		n->dirty = true;
		n->type = inode::TYPE_DIRECTORY;
		n->nlink = 2;
		n->size = 2;
		n->mtime = get_wt_now();

		n->files.emplace_back(".", 1, inode::TYPE_DIRECTORY);
		n->files.emplace_back("..", 1, inode::TYPE_DIRECTORY);

		mark_inode_allocated(1);
		inode_directory.cached_inodes.insert({1, n});
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
			while (client->rd_buf_pos >= 4)
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

		case prot::client::req::READDIR:
			return process_client_message(
					client,
					static_cast<prot::client::req::readdir&>(*msg));

		case prot::client::req::CREATE:
			return process_client_message(
					client,
					static_cast<prot::client::req::create&>(*msg));

		case prot::client::req::READ:
			return process_client_message(
					client,
					static_cast<prot::client::req::read&>(*msg));

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
	reply.size_total = data_map.total_data_size;
	reply.size_used = 0;

	reply.inodes_total = data_map.total_inode_count;
	reply.inodes_used = inode_directory.allocated_count;

	return send_message_to_client(client, reply);
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::getfattr& msg)
{
	/* GETFATTR */
	/* Lock inode */
	/* Read inode */
	/* Unlock inode */
	/* Return information */

	if (msg.node_id == 0)
	{
		prot::client::reply::getfattr reply;
		reply.req_id = msg.req_id;
		reply.res = err::INVAL;
		return send_message_to_client(client, reply);
	}

	/* Lock inode */
	inode_lock_request_t lck_req;
	lck_req.node_id = msg.node_id;
	lck_req.write = false;
	lck_req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_getfattr_ilock,
			this, client, msg.req_id);

	lock_inode(lck_req);

	return false;
}

void ctrl_ctx::cb_c_r_getfattr_ilock(
		shared_ptr<ctrl_client> client, req_id_t req_id, inode_lock_request_t& lck_req)
{
	inode_lock_witness w(bind_front(&ctrl_ctx::unlock_inode, this), lck_req);

	/* Read inode */
	get_inode_request_t req;
	req.ilocks.push_back(move(w));
	req.node_id = lck_req.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_getfattr_inode,
			this, client, req_id);

	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_getfattr_inode(
		shared_ptr<ctrl_client> client, req_id_t req_id, get_inode_request_t&& req)
{
	prot::client::reply::getfattr reply;
	reply.req_id = req_id;
	reply.res = req.result;

	if (req.result == err::SUCCESS)
	{
		if (req.node->type == inode::TYPE_FILE || req.node->type == inode::TYPE_DIRECTORY)
		{
			reply.type = req.node->type == inode::TYPE_FILE ?
				prot::client::reply::FT_FILE :
				prot::client::reply::FT_DIRECTORY;

			reply.nlink = req.node->nlink;
			reply.mtime = req.node->mtime;
			reply.size = req.node->size;
		}
		else
		{
			reply.res = err::NOENT;
		}
	}

	/* Unlock inode */
	req.ilocks.clear();

	/* Return information */
	send_message_to_client(client, reply);
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::readdir& msg)
{
	/* Lock inode */
	/* Read inode */
	/*   i* Lock extension inode */
	/*      Read extension inode */
	/*   i* Unlock extension inode */
	/* Unlock inode */
	/* Return information */

	if (msg.node_id == 0)
	{
		prot::client::reply::readdir reply;
		reply.req_id = msg.req_id;
		reply.res = err::INVAL;
		return send_message_to_client(client, reply);
	}

	/* Lock inode */
	inode_lock_request_t lck_req;
	lck_req.node_id = msg.node_id;
	lck_req.write = false;
	lck_req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_readdir_ilock,
			this, client, msg.req_id);

	lock_inode(lck_req);

	return false;
}

void ctrl_ctx::cb_c_r_readdir_ilock(
		shared_ptr<ctrl_client> client, req_id_t req_id, inode_lock_request_t& lck_req)
{
	inode_lock_witness w(bind_front(&ctrl_ctx::unlock_inode, this), lck_req);

	/* Read inode */
	get_inode_request_t req;
	req.ilocks.push_back(move(w));
	req.node_id = lck_req.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_readdir_inode,
			this, client, req_id);

	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_readdir_inode(
		shared_ptr<ctrl_client> client, req_id_t req_id, get_inode_request_t&& req)
{
	prot::client::reply::readdir reply;
	reply.req_id = req_id;
	reply.res = req.result;

	{
		auto& node = *req.node;

		if (req.result == err::SUCCESS)
		{
			if (node.type == inode::TYPE_DIRECTORY)
			{
				for (const auto& [name, cnid, f_type] : node.files)
				{
					prot::client::reply::readdir::entry re;

					re.name = name;
					re.node_id = cnid;
					re.type = f_type == inode::TYPE_DIRECTORY ?
						prot::client::reply::FT_DIRECTORY :
						prot::client::reply::FT_FILE;

					reply.entries.push_back(re);
				}
			}
			else if (node.type == inode::TYPE_FILE)
			{
				reply.res = err::NOTDIR;
			}
			else
			{
				reply.res = err::NOENT;
			}
		}
	}

	/* Unlock inodes */
	req.ilocks.clear();

	/* Return information */
	send_message_to_client(client, reply);
}


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::create& msg)
{
	/* CREATE */
	/* Lock inode allocator */
	/* Get free inode */
	/* Lock new inode w */
	/* Initialize inode */
	/* Lock parent inode w */
	/* Get parent inode */
	/*   Get free inode (as extension) */
	/*   Lock new inode w */
	/*   Write extension inode */
	/*   Update original inode */
	/* Add link */
	/* Unlock inodes */
	/* Unlock inode allocator */
	/* Inform client */

	if (msg.parent_node_id == 0)
	{
		return send_message_to_client(
				client,
				prot::client::reply::create(msg.req_id, err::INVAL));
	}

	if (msg.name.size() == 0 || msg.name.size() > 255)
	{
		/* Linux open appears to return ENOENT if given the empty string as
		 * filename. */
		return send_message_to_client(
				client, 
				prot::client::reply::create(
					msg.req_id,
					msg.name.size() ? err::NAMETOOLONG : err::NOENT));
	}

	/* Lock inode allocator */
	auto rctx = make_shared<ctx_c_r_create>(msg);
	rctx->client = client;

	inode_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_create_ialloc, this, rctx);

	lock_inode_allocator(req);

	return false;
}

void ctrl_ctx::cb_c_r_create_ialloc(shared_ptr<ctx_c_r_create> rctx, inode_allocator_lock_request_t& alck)
{
	rctx->ialloc_lck = inode_allocator_lock_witness(
			bind_front(&ctrl_ctx::unlock_inode_allocator, this), alck);

	/* Get free inode */
	auto node_id = get_free_inode();
	if (node_id < 0)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, err::NOSPC));

		return;
	}

	rctx->node_id = node_id;
	rctx->node = make_shared<inode>();

	/* Lock new inode w */
	inode_lock_request_t req;

	req.node_id = node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_create_ilock, this, rctx);

	lock_inode(req);
}

void ctrl_ctx::cb_c_r_create_ilock(shared_ptr<ctx_c_r_create> rctx, inode_lock_request_t& ilck)
{
	rctx->n_ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Initialize inode */
	rctx->node->dirty = true;

	rctx->node->type = inode::TYPE_FILE;
	rctx->node->nlink = 1;
	rctx->node->mtime = get_wt_now();
	rctx->node->size = 100 * 1024 * 1024;
	rctx->node->allocations.emplace_back(0, 100 * 1024 * 1024);

	/* Lock parent inode w */
	inode_lock_request_t req;
	req.node_id = rctx->msg.parent_node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_create_ilockp, this, rctx);
	lock_inode(req);
}

void ctrl_ctx::cb_c_r_create_ilockp(shared_ptr<ctx_c_r_create> rctx, inode_lock_request_t& ilck)
{
	rctx->p_ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Get parent inode */
	get_inode_request_t req;
	req.node_id = rctx->msg.parent_node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_create_getp, this, rctx);
	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_create_getp(shared_ptr<ctx_c_r_create> rctx, get_inode_request_t&& ireq)
{
	if (ireq.result != err::SUCCESS)
	{
		/* NOTE: At this point the new inode has not been marked as allocated or
		 * stored anywhere yet. Hence we can simply return and no effect will be
		 * created. */
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, ireq.result));

		return;
	}

	if (ireq.node->type != inode::TYPE_DIRECTORY)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, err::NOTDIR));

		return;
	}

	rctx->parent_node = ireq.node;

	/* Check if directory entry fits into directory */
	if (!rctx->parent_node->enough_space_for_file(rctx->msg.name))
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, err::NOSPC));

		return;
	}

	/* Mark new inode as allocated and add it to the inode cache */
	mark_inode_allocated(rctx->node_id);
	inode_directory.cached_inodes.insert_or_assign(rctx->node_id, rctx->node);

	/* Add link */
	rctx->parent_node->dirty = true;
	rctx->parent_node->files.emplace_back(rctx->msg.name, rctx->node_id, inode::TYPE_FILE);
	rctx->parent_node->size++;

	/* Unlock inodes and inode allocator, and inform client */
	prot::client::reply::create reply(rctx->msg.req_id, err::SUCCESS);
	reply.node_id = rctx->node_id;
	reply.nlink = rctx->node->nlink;
	reply.mtime = rctx->node->mtime;
	reply.size = rctx->node->size;

	send_message_to_client(rctx->client, reply);
}


/* UNLINK */
/* Lock inode allocator */
/* Lock inode w */
/* Remove inode */
/* Free blocks */
/* Unlock inode w */
/* Unlock inode allocator */

/* MKDIR */
/* like CREATE */


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::read& msg)
{
	/* READ */
	/* b Lock inode */
	/* b Retrieve data map(s) */
	/* b Read data */
	/*   Unlock inode */
	/*   Assemble data */
	/*   Return data */

	// printf("read %d bytes\n", (int) msg.size);

	if (msg.node_id == 0)
	{
		return send_message_to_client(
				client,
				prot::client::reply::read(msg.req_id, err::INVAL));
	}

	auto rctx = make_shared<ctx_c_r_read>(msg);
	rctx->client = client;
	rctx->t_start = get_monotonic_time();

	/* Lock inode */
	inode_lock_request_t req;

	req.node_id = rctx->msg.node_id;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_read_ilock, this, rctx);

	lock_inode(req);

	return false;
}

void ctrl_ctx::cb_c_r_read_ilock(shared_ptr<ctx_c_r_read> rctx, inode_lock_request_t& ilck)
{
	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve data map(s) */
	get_inode_request_t req;

	req.node_id = rctx->msg.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_read_getnode, this, rctx);
	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_read_getnode(shared_ptr<ctx_c_r_read> rctx, get_inode_request_t&& ireq)
{
	if (ireq.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, ireq.result));
		return;
	}

	if (ireq.node->type != inode::TYPE_FILE)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::create(rctx->msg.req_id, err::ISDIR));
		return;
	}

	rctx->node = ireq.node;


	/* Determine which data must be read and from which dds */
	if (rctx->msg.offset >= rctx->node->size || rctx->msg.size == 0)
	{
		/* EOF or read size 0 */
		send_message_to_client(
				rctx->client,
				prot::client::reply::read(rctx->msg.req_id, err::SUCCESS));
		return;
	}

	rctx->read_size_total = min(rctx->msg.size, rctx->node->size - rctx->msg.offset);

	/* Map data to dds */
	for (auto [b_o, b_s, b_file_o] : map_file_region(*(rctx->node), rctx->msg.offset, rctx->read_size_total))
	{
		auto b_num = b_o / data_map.block_size;
		auto dd = data_map.dd_rr_order[b_num % data_map.n_dd];
		auto dd_offset = b_o - b_num * data_map.block_size;
		rctx->blocks.emplace_back(b_file_o - rctx->msg.offset, b_s, dd, dd_offset);
	}


	/* Read data from dds */
	for (size_t i = 0; i < rctx->blocks.size(); i++)
	{
		auto& b = rctx->blocks[i];

		dd_read_request_t req;

		req.dd = b.dd;
		req.offset = b.dd_offset;
		req.size = b.size;
		req.cb_completed = bind_front(&ctrl_ctx::cb_c_r_read_dd, this, rctx, i);

		dd_read(move(req));
	}
}

void ctrl_ctx::cb_c_r_read_dd(shared_ptr<ctx_c_r_read> rctx, size_t bi,
		dd_read_request_t&& req)
{
	/* Store result of read request */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		if (req.data)
		{
			b.data = req.data;
			b._buf = move(req._buf);
		}

		b.completed = true;
	}

	/* Test if all read requests have completed */
	for (auto& b : rctx->blocks)
	{
		if (!b.completed)
			return;
	}

	/* Check return codes of individual block read requests */
	for (auto& b : rctx->blocks)
	{
		if (b.result != err::SUCCESS)
		{
			send_message_to_client(
					rctx->client,
					prot::client::reply::read(rctx->msg.req_id, b.result));
			return;
		}
	}

	/* Unlock inode */
	rctx->ilck = inode_lock_witness();

	if (rctx->client->invalid)
		return;

	/* Assemble data */
	prot::client::reply::read reply(rctx->msg.req_id, err::SUCCESS);
	reply.size = rctx->read_size_total;
	dynamic_buffer buf;
	buf.ensure_size(reply.serialize(nullptr) + reply.size);
	auto reply_size = reply.serialize(buf.ptr());
	auto data_ptr = buf.ptr() + reply_size;
	auto data_end = buf.ptr() + buf.size();
	reply_size += reply.size;

	for (const auto& b : rctx->blocks)
	{
		if (data_ptr + b.offset + b.size >= data_end)
		{
			printf("%p -> %p; off: 0x%08x, size: %d\n",
					data_ptr, data_end, (int) b.offset, (int) b.size);

			throw runtime_error("Internal buffer overflow");
		}

		memcpy(data_ptr + b.offset, b.data, b.size);
	}

	/* Return data to client */
	send_message_to_client(rctx->client, move(buf), reply_size);

	double diff = (get_monotonic_time() - rctx->t_start) / 1e9;
	printf("read processing took %fms for %d bytes\n",
			diff * 1e3, (int) rctx->msg.size);
}


/* Write */
/* Lock inode w */
/* Retrieve data map(s) */
/*   Lock block allocator */
/*   Get free blocks */
/*   Unlock block allocator */
/* Update timestamps and size if required */
/* Unlock inode w */
/* Split data */
/* Write data */
/* Inform client */





bool ctrl_ctx::send_message_to_client(shared_ptr<ctrl_client> client, const prot::msg& msg)
{
	if (client->invalid)
		return true;

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


void ctrl_ctx::main()
{
	while (!quit_requested)
		epoll.process_events(-1);
}


void ctrl_ctx::lock_inode(inode_lock_request_t& req)
{
	if (req.node_id == 0)
		throw invalid_argument("invalid inode id 0");

	auto [ilck,inserted] = inode_directory.node_locks.insert({
			req.node_id,
			inode_directory_t::node_lock_t()});

	auto& lck = ilck->second;

	/* NOTE: This may starve write lock requesters, but thats ok for now */
	if (lck.lockers == 0 || (lck.lockers > 0 && !req.write))
	{
		/* Immediately grant lock */
		if (req.write)
			lck.lockers--;
		else
			lck.lockers++;

		/* NOTE: It is very important that unlock_inode can be called from this
		 * callback for any inode id
		 *
		 * NOTE: cb_aquired might reference a shared_ptr (partially evaluated
		 * function) to an object, which might contain a copy of req. This would
		 * lead to a depenency loop of the shared_ptr. To prevent this and as
		 * cb_acquired will not be needed anymore after calling it here, pass a
		 * copy of req to cb_acquired which has cb_acquired set to nullptr. */
		inode_lock_request_t r2(req);
		r2.cb_acquired = nullptr;

		auto cb = req.cb_acquired;
		cb(r2);
	}
	else
	{
		lck.reqs.emplace_back(req);
	}
}

void ctrl_ctx::unlock_inode(inode_lock_request_t& req)
{
	if (req.node_id == 0)
		throw invalid_argument("invalid inode id 0");

	{
		auto ilck = inode_directory.node_locks.find(req.node_id);
		if (ilck == inode_directory.node_locks.end())
			throw invalid_argument("No such lock");

		auto& lck = ilck->second;

		if (
				(lck.lockers > -1 && req.write) ||
				(lck.lockers < 1 && !req.write))
		{
			throw invalid_argument("Invalid lock mode / lock not held");
		}

		if (req.write)
			lck.lockers++;
		else
			lck.lockers--;
	}

	/* Process pending lock requests; this is tricky when unlock_inode is called
	 * recursively on the same node id. The innermost invocation will always try
	 * to process as many requests as possible, and the outer invocations will
	 * each try to process as many requests as possible, too. Each inner
	 * invocation can delete the lock structure, hence it needs to be
	 * retrieved during each loop iteration. */
	for (;;)
	{
		auto ilck = inode_directory.node_locks.find(req.node_id);
		if (ilck == inode_directory.node_locks.end())
			break;

		auto& lck = ilck->second;

		if (
				lck.reqs.empty() ||
				(lck.reqs.front().write && lck.lockers != 0) ||
				(!lck.reqs.front().write && lck.lockers < 0))
		{
			break;
		}

		auto r = lck.reqs.front();
		lck.reqs.pop_front();

		if (r.write)
			lck.lockers--;
		else
			lck.lockers++;

		auto cb = r.cb_acquired;
		r.cb_acquired = nullptr;
		cb(r);
	}

	/* Remove the lock structure if it is still present and empty. */
	{
		auto ilck = inode_directory.node_locks.find(req.node_id);
		if (
				ilck != inode_directory.node_locks.end() &&
				ilck->second.lockers == 0 &&
				ilck->second.reqs.size())
		{
			inode_directory.node_locks.erase(ilck);
		}
	}
}


void ctrl_ctx::lock_inode_allocator(inode_allocator_lock_request_t& req)
{
	if (!inode_directory.allocator_locked)
	{
		inode_directory.allocator_locked = true;

		/* NOTE: It is very important that unlock_inode_allocator can be called
		 * from this callback.
		 *
		 * NOTE: cb_aquired might reference a shared_ptr (partially evaluated
		 * function) to an object, which might contain a copy of req. This would
		 * lead to a depenency loop of the shared_ptr. To prevent this and as
		 * cb_acquired will not be needed anymore after calling it here, pass a
		 * copy of req to cb_acquired which has cb_acquired set to nullptr. */
		inode_allocator_lock_request_t r2(req);
		r2.cb_acquired = nullptr;

		auto cb = req.cb_acquired;
		cb(r2);
	}
	else
	{
		inode_directory.allocator_lock_reqs.push_back(req);
	}
}

void ctrl_ctx::unlock_inode_allocator(inode_allocator_lock_request_t& req)
{
	if (!inode_directory.allocator_locked)
		throw invalid_argument("Lock not held");

	inode_directory.allocator_locked = false;

	/* Process pending lock requests; Note that the cb_acquired function
	 * supplied by the lock requester might call unlock_inode_allocator, too.
	 * This leads to recursive invocation of this function. The innermost
	 * invocation will run its loop as long as possible, and than the outer
	 * invocations will continue. Hence it is important the check the state of
	 * the lock after each run and take into account that the lock queue might
	 * change. */
	while (!inode_directory.allocator_locked &&
			inode_directory.allocator_lock_reqs.size())
	{
		inode_directory.allocator_locked = true;

		auto r = inode_directory.allocator_lock_reqs.front();
		inode_directory.allocator_lock_reqs.pop_front();

		auto cb = r.cb_acquired;
		r.cb_acquired = nullptr;
		cb(r);
	}
}


void ctrl_ctx::get_inode(get_inode_request_t&& req)
{
	/* If inode is in cache, return it */
	auto i = inode_directory.cached_inodes.find(req.node_id);
	if (i != inode_directory.cached_inodes.end())
	{
		req.node = i->second;
		req.result = err::SUCCESS;

		/* Same problem as in lock_inode */
		auto cb = req.cb_finished;
		req.cb_finished = nullptr;
		cb(move(req));
		return;
	}

	/* Retrieve inode */
	req.result = err::NOENT;
	auto cb = req.cb_finished;
	req.cb_finished = nullptr;
	cb(move(req));
}


void ctrl_ctx::mark_inode_allocated(unsigned long node_id)
{
	if (node_id >= data_map.total_inode_count || node_id == 0)
		throw invalid_argument("Inode id out of range");

	auto off = node_id / 8;
	auto mask = 1 << (node_id % 8);
	if (inode_directory.allocator_bitmap[off] & mask)
		throw runtime_error("Inode already allocated");

	inode_directory.allocator_bitmap[off] |= mask;

	inode_directory.allocator_dirty = true;
	inode_directory.allocated_count++;
}

void ctrl_ctx::mark_inode_unallocated(unsigned long node_id)
{
	if (node_id >= data_map.total_inode_count || node_id == 0)
		throw invalid_argument("Inode id out of range");

	auto off = node_id / 8;
	auto mask = 1 << (node_id % 8);
	if (!(inode_directory.allocator_bitmap[off] & mask))
		throw runtime_error("Inode already unallocated");

	inode_directory.allocator_bitmap[off] &= ~mask;

	inode_directory.allocator_dirty = true;
	inode_directory.allocated_count--;
}

long ctrl_ctx::get_free_inode()
{
	for (unsigned long i = 1; i < data_map.total_inode_count; i++)
	{
		auto off = i / 8;
		auto mask = 1 << (i % 8);

		if (!(inode_directory.allocator_bitmap[off] & mask))
			return i;
	}

	return -1;
}


vector<tuple<size_t, size_t, size_t>> ctrl_ctx::map_file_region(
		const inode& node, size_t offset, size_t size)
{
	vector<tuple<size_t, size_t, size_t>> blocks;

	/* Find first chunk mapping; note that this is actually O(n) but could be
	 * implemented in O(log(n)) by storing the in-file offsets in the (cached)
	 * allocation table. However the allocation table should be small enough
	 * s.t. this is can be considered expected-constant-time. */
	size_t pos = 0;
	auto i_alloc = node.allocations.begin();
	for (; i_alloc != node.allocations.end(); i_alloc++)
	{
		if (pos <= offset && offset < pos + i_alloc->size)
			break;

		pos += i_alloc->size;
	}

	/* Iterate through all chunk mappings */
	for (; i_alloc != node.allocations.end(); i_alloc++)
	{
		if (pos >= offset + size)
			break;

		size_t chunk_offset;
		size_t chunk_size;
		size_t chunk_file_offset;

		if (pos >= offset)
		{
			chunk_offset = i_alloc->offset;
			chunk_file_offset = pos;
			chunk_size = min(i_alloc->size, offset + size - chunk_file_offset);
		}
		else
		{
			chunk_offset = i_alloc->offset + (offset - pos);
			chunk_file_offset = offset;
			chunk_size = min(pos + i_alloc->size - chunk_file_offset, size);
		}

		// printf("DEBUG: chunk_size: %d, chunk_offset: %d, chunk_file_offset: %d\n",
		// 		(int) chunk_size, (int) chunk_offset, (int) chunk_file_offset);

		/* Map chunk to blocks */
		auto chunk_end = chunk_offset + chunk_size;
		auto current_block = chunk_offset / data_map.block_size;
		for (;;)
		{
			auto current_block_start = current_block * data_map.block_size;
			if (current_block_start >= chunk_end)
				break;

			size_t block_offset;
			size_t block_size;
			size_t block_file_offset;

			if (current_block_start >= chunk_offset)
			{
				block_offset = current_block_start;
				block_size = min(chunk_end - current_block_start, data_map.block_size);
				block_file_offset = chunk_file_offset + (current_block_start - chunk_offset);
			}
			else
			{
				block_offset = chunk_offset;
				block_size = min(chunk_size, data_map.block_size - (chunk_offset - current_block_start));
				block_file_offset = chunk_file_offset;
			}

			// printf("DEBUG: block_size: %d, block_offset: %d, block_file_offset: %d\n",
			// 		(int) block_size, (int) block_offset, (int) block_file_offset);

			blocks.emplace_back(block_offset, block_size, block_file_offset);

			current_block++;
		}

		pos += i_alloc->size;
	}

	return blocks;
}


void ctrl_ctx::dd_read(dd_read_request_t&& req)
{
	char c = 'a' + req.dd->id % 0x10;

	req.result = err::SUCCESS;
	req._buf.ensure_size(req.size);
	memset(req._buf.ptr(), c, req.size);
	req.data = req._buf.ptr();

	auto cb = req.cb_completed;
	cb(move(req));
}
