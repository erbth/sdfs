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

				addr.sin6_addr = ((const struct sockaddr_in6&) ai->ai_addr).sin6_addr;

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

	epoll.add_fd(wfd.get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP,
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

void ctrl_ctx::initialize(bool format)
{
	format_on_startup = format;
	if (format_on_startup)
		printf("Filesystem will be formatted.\n\n");

	/* Read config file and check values */
	initialize_cfg();

	/* Connect to dds */
	initialize_connect_dds();

	/* Build data map and initialize inode directory */
	build_data_map();
	initialize_block_allocator();
	initialize_inode_directory();
	initialize_root_directory();

	/* Create listening sockets */
	initialize_client_listener();

	/* Start background job */
	background_job_enabled = true;
	bg_tfd.start(10000000);
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


void ctrl_ctx::initialize_block_allocator()
{
	block_allocator._buffer = fixed_aligned_buffer(
			4096, data_map.allocation_bitmap_size);

	block_allocator.bitmap = (uint8_t*) block_allocator._buffer.ptr();

	memset(block_allocator.bitmap, 0, data_map.allocation_bitmap_size);

	/* Read block allocation bitmap from first dd */
	if (!format_on_startup)
	{
		auto dd = &dds.front();
		auto buf = dd_read_sync_startup(
				dd,
				dd->allocation_bitmap_offset,
				data_map.allocation_bitmap_size);

		if (buf.get_size() != data_map.allocation_bitmap_size)
			throw runtime_error("Failed to read block allocation bitmap");

		memcpy(block_allocator.bitmap, buf.ptr(), data_map.allocation_bitmap_size);
	}
	else
	{
		block_allocator.dirty = true;
	}

	/* Initialize allocated block count */
	block_allocator.allocated_count = 0;
	for (size_t i = 0; i < data_map.allocation_bitmap_size * 8; i++)
	{
		auto off = i / 8;
		auto mask = 1 << (i % 8);

		if (block_allocator.bitmap[off] & mask)
			block_allocator.allocated_count++;
	}
}


void ctrl_ctx::initialize_inode_directory()
{
	size_t bitmap_disk_size = (data_map.total_inode_count + 7) / 8;
	if (bitmap_disk_size > 100 * 1024 * 1024ULL)
		throw runtime_error("Inode directory allocator too large");

	auto alloc_size = (bitmap_disk_size + 4095) & ~(4095ULL);

	inode_directory._allocator_buffer = fixed_aligned_buffer(4096, alloc_size);
	inode_directory.allocator_bitmap = (uint8_t*) inode_directory._allocator_buffer.ptr();

	memset(inode_directory.allocator_bitmap, 0, alloc_size);

	/* Read inode allocation bitmap from first dd */
	if (!format_on_startup)
	{
		auto dd = &dds.front();
		auto buf = dd_read_sync_startup(
				dd,
				dd->inode_bitmap_offset,
				bitmap_disk_size);

		if (buf.get_size() != bitmap_disk_size)
			throw runtime_error("Failed to read imap allocator bitmap");

		memcpy(inode_directory.allocator_bitmap, buf.ptr(), bitmap_disk_size);
	}
	else
	{
		inode_directory.allocator_dirty = true;
	}

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
	/* Create the root directory if it does not exist yet. */
	if ((inode_directory.allocator_bitmap[0] & 0x01) == 0)
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


void ctrl_ctx::on_background_timer()
{
	if (!background_job_enabled)
		return;

	purge_unreferenced_inodes();

	/* Note that it is no problem if two store_metadata calls overlap, as long
	 * as the dds are not overwhelmed by the IO they generated. All resources
	 * are protected by locks. */
	store_metadata();
}


void ctrl_ctx::on_epoll_ready(int res)
{
	if (res < 0)
		throw runtime_error("async poll on epoll fd failed");

	epoll.process_events(0);

	io_uring.submit_poll(epoll.get_fd(), POLLIN,
			bind_front(&ctrl_ctx::on_epoll_ready, this));
}


void ctrl_ctx::on_client_lfd(int fd, uint32_t events)
{
	if (stop_accepting_new_clients)
	{
		epoll.remove_fd(client_lfd.get_fd());
		return;
	}

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


void ctrl_ctx::on_dd_fd(ctrl_dd* dd, int fd, uint32_t events)
{
	if (fd != dd->get_fd())
		throw runtime_error("Got epoll event for invalid dd fd");

	bool disconnect = false;

	/* Send data */
	if (events & EPOLLOUT)
	{
		// auto prof = profiler_get("on_dd_fd(send)");

		bool disable_sender = false;
		if (dd->send_queue.size() > 0)
		{
			auto& qmsg = dd->send_queue.front();

			size_t to_write = min(
					2 * 1024UL * 1024,
					qmsg.msg_len - dd->send_msg_pos);

			auto ret = write(
					dd->get_fd(),
					qmsg.buf_ptr() + dd->send_msg_pos,
					to_write);

			if (ret >= 0)
			{
				dd->send_msg_pos += ret;
				if (dd->send_msg_pos == qmsg.msg_len)
				{
					qmsg.return_buffer(buf_pool_dd_io);
					dd->send_queue.pop();
					dd->send_msg_pos = 0;

					if (dd->send_queue.empty())
						disable_sender = true;
				}
			}
			else
			{
				disconnect = true;
			}
		}
		else
		{
			disable_sender = true;
		}

		if (disable_sender)
			epoll.change_events(dd->get_fd(), EPOLLIN | EPOLLHUP | EPOLLRDHUP);
	}

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

	auto was_empty = dd.send_queue.empty();
	dd.send_queue.emplace(move(buf), msg_len);

	if (was_empty)
		epoll.change_events(dd.get_fd(), EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

	return false;
}


void ctrl_ctx::on_client_fd(shared_ptr<ctrl_client> client, int fd, uint32_t events)
{
	if (fd != client->get_fd())
		throw runtime_error("Got epoll event for invalid fd");

	bool rm_client = false;

	/* Read data */
	bool have_r_event = events & EPOLLIN;
	if (have_r_event && stop_accepting_client_requests)
	{
		have_r_event = false;
		epoll.change_events(client->get_fd(), EPOLLHUP | EPOLLRDHUP);
	}

	if (have_r_event)
	{
		// auto prof = profiler_get("on_client_fd(recv)");

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

void ctrl_ctx::on_client_writev_finished(shared_ptr<ctrl_client> client, int res)
{
	// auto prof = profiler_get("on_client_writev_finished");

	io_uring_req_in_flight--;

	if (res < 0)
	{
		remove_client(client);
		return;
	}

	client->send_msg_pos += res;

	/* Remove all messages that have been sent */
	auto qmsg = &client->send_queue.front();

	while (client->send_msg_pos >= qmsg->msg_len)
	{
		qmsg->return_buffer(buf_pool_req);
		client->send_msg_pos -= qmsg->msg_len;
		client->send_queue.pop_front();

		if (client->send_queue.empty())
		{
			if (client->send_msg_pos != 0)
				throw runtime_error("send_msg_pos should be 0 on empty queue");

			return;
		}

		qmsg = &client->send_queue.front();
	}

	/* Submit messages on queue */
	if (io_uring_req_in_flight >= io_uring_max_req_in_flight)
		throw runtime_error("io uring instance full");

	unsigned cnt_msgs = 0;
	auto iq = client->send_queue.begin();

	auto offset = client->send_msg_pos;

	for (;
			cnt_msgs < sizeof(client->send_iovs) / sizeof(client->send_iovs[0]) &&
				iq != client->send_queue.end();
			cnt_msgs++, iq++)
	{
		if (offset >= iq->msg_len)
			throw runtime_error("offset > iq->msg_len()");

		auto& iov = client->send_iovs[cnt_msgs];
		iov.iov_base = (char*) iq->buf_ptr() + offset;
		iov.iov_len = iq->msg_len - offset;

		offset = 0;
	}

	io_uring.queue_writev(
			client->get_fd(),
			client->send_iovs, cnt_msgs, -1,
			0,
			bind_front(&ctrl_ctx::on_client_writev_finished, this, client));

	io_uring.submit();

	io_uring_req_in_flight++;
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, dynamic_buffer&& buf, size_t msg_len)
{
	// auto prof = profiler_get("process_client_message");

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

	if (!client->mp_client && msg->num != prot::client::req::CONNECT)
	{
		fprintf(stderr, "Protocol violation by client.\n");
		return true;
	}

	switch (msg->num)
	{
		case prot::client::req::CONNECT:
			return process_client_message(
					client,
					static_cast<prot::client::req::connect&>(*msg));

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

		case prot::client::req::UNLINK:
			return process_client_message(
					client,
					static_cast<prot::client::req::unlink&>(*msg));

		case prot::client::req::FORGET:
			return process_client_message(
					client,
					static_cast<prot::client::req::forget&>(*msg));

		case prot::client::req::READ:
			return process_client_message(
					client,
					static_cast<prot::client::req::read&>(*msg));

		case prot::client::req::WRITE:
			return process_client_message(
					client,
					static_cast<prot::client::req::write&>(*msg),
					move(buf));

		default:
			fprintf(stderr, "client io: protocol violation\n");
			return true;
	}
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::connect& msg)
{
	prot::client::reply::connect reply(msg.req_id);

	/* Ensure that the client is not connected already */
	if (client->mp_client)
	{
		fprintf(stderr, "duplicate CONNECT message from client\n");
		return true;
	}

	if (msg.client_id == 0)
	{
		/* New client; allocate a client id */
		client->mp_client = create_mp_client();
		reply.client_id = client->mp_client->id;
	}
	else
	{
		/* New path for exisiting client; find client */
		client->mp_client = find_mp_client(msg.client_id);
		if (!client->mp_client)
		{
			fprintf(stderr, "new path references invalid client during CONNECT\n");
			return true;
		}

		reply.client_id = msg.client_id;
	}

	return send_message_to_client(client, reply);
}

bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::getattr& msg)
{
	prot::client::reply::getattr reply;

	reply.req_id = msg.req_id;

	reply.size_total = data_map.total_data_size;
	reply.size_used = block_allocator.allocated_count * data_map.allocation_granularity;

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
			reply.allocated_size = req.node->get_allocated_size();

			/* Reference inode */
			inode_add_client_ref(req.node, client);
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
	rctx->node->size = 0;

	/* Reference inode */
	inode_add_client_ref(rctx->node, rctx->client);

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
	rctx->parent_node->mtime = get_wt_now();

	/* Unlock inodes and inode allocator, and inform client */
	prot::client::reply::create reply(rctx->msg.req_id, err::SUCCESS);
	reply.node_id = rctx->node_id;
	reply.nlink = rctx->node->nlink;
	reply.mtime = rctx->node->mtime;
	reply.size = rctx->node->size;

	send_message_to_client(rctx->client, reply);
}


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::unlink& msg)
{
	/* UNLINK */
	/* b Lock parent inode w */
	/* b Retrieve parent inode */
	/*   Find link to inode */
	/* b Lock inode w */
	/* b Retrieve inode */
	/*   Remove link */

	if (msg.parent_node_id == 0 || msg.name.size() == 0)
	{
		return send_message_to_client(
				client,
				prot::client::reply::unlink(msg.req_id, err::INVAL));
	}

	auto rctx = make_shared<ctx_c_r_unlink>(msg);
	rctx->client = client;

	/* Lock parent inode w */
	inode_lock_request_t req;

	req.node_id = rctx->msg.parent_node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_unlink_ilock, this, rctx);
	lock_inode(req);

	return false;
}

void ctrl_ctx::cb_c_r_unlink_ilock(
		shared_ptr<ctx_c_r_unlink> rctx, inode_lock_request_t& ilck)
{
	rctx->p_ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve parent inode */
	get_inode_request_t req;

	req.node_id = rctx->msg.parent_node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_unlink_getnode, this, rctx);
	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_unlink_getnode(
		shared_ptr<ctx_c_r_unlink> rctx, get_inode_request_t&& ireq)
{
	if (ireq.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::unlink(rctx->msg.req_id, ireq.result));
		return;
	}

	rctx->parent_node = ireq.node;

	if (rctx->parent_node->type != inode::TYPE_DIRECTORY)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::unlink(rctx->msg.req_id, err::NOTDIR));
		return;
	}

	/* Find link to inode */
	bool found = false;

	for (const auto& [name, node_id, node_type] : rctx->parent_node->files)
	{
		if (name == rctx->msg.name)
		{
			if (node_type != inode::TYPE_FILE)
			{
				send_message_to_client(
						rctx->client,
						prot::client::reply::unlink(rctx->msg.req_id, err::ISDIR));
				return;
			}

			found = true;
			rctx->entry_node_id = node_id;
			break;
		}
	}

	if (!found)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::unlink(rctx->msg.req_id, err::NOENT));
		return;
	}

	/* Lock inode w */
	inode_lock_request_t req;

	req.node_id = rctx->entry_node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_unlink_lock_entry, this, rctx);

	lock_inode(req);
}

void ctrl_ctx::cb_c_r_unlink_lock_entry(
		shared_ptr<ctx_c_r_unlink> rctx, inode_lock_request_t& ilck)
{
	rctx->e_ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve inode */
	get_inode_request_t req;

	req.node_id = rctx->entry_node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_unlink_get_entry, this, rctx);

	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_unlink_get_entry(
		shared_ptr<ctx_c_r_unlink> rctx, get_inode_request_t&& req)
{
	if (req.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::unlink(rctx->msg.req_id, req.result));
		return;
	}

	auto entry = req.node;

	/* Remove link */
	auto entry_node_id = rctx->entry_node_id;
	auto i = find_if(
			rctx->parent_node->files.begin(),
			rctx->parent_node->files.end(),
			[entry_node_id](auto& e){ return get<1>(e) == entry_node_id; });

	if (i == rctx->parent_node->files.end())
		throw runtime_error("Directory entry disappeared during unlink");

	rctx->parent_node->files.erase(i);
	rctx->parent_node->dirty = true;

	if (entry->nlink == 0)
		throw runtime_error("Unlink on inode with link count 0");

	entry->nlink--;
	entry->dirty = true;

	send_message_to_client(
			rctx->client,
			prot::client::reply::unlink(rctx->msg.req_id, err::SUCCESS));
}


/* MKDIR */
/* like CREATE */


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::forget& msg)
{
	/* NOTE: This procedure does not guarantee consistend block/inode/inode
	 * directory metadata on unclean shutdown. */

	/* FORGET */
	/* b Lock inode allocator */
	/* b Lock inode w */
	/* b Retrieve inode */
	/*   Delete inode if not referenced anymore: */
	/*     b Lock block allocator */
	/*       Unallocate ranges */
	/*       Unallocate inode */

	if (msg.node_id == 0)
	{
		return send_message_to_client(
				client,
				prot::client::reply::forget(msg.req_id, err::INVAL));
	}

	auto rctx = make_shared<ctx_c_r_forget>(msg);
	rctx->client = client;

	/* Lock inode allocator */
	inode_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_forget_ialck, this, rctx);

	lock_inode_allocator(req);
	return false;
}

void ctrl_ctx::cb_c_r_forget_ialck(
		shared_ptr<ctx_c_r_forget> rctx, inode_allocator_lock_request_t& ialck)
{
	rctx->ialck = inode_allocator_lock_witness(
			bind_front(&ctrl_ctx::unlock_inode_allocator, this), ialck);

	/* Lock inode w */
	inode_lock_request_t req;

	req.node_id = rctx->msg.node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_forget_ilck, this, rctx);

	lock_inode(req);
}

void ctrl_ctx::cb_c_r_forget_ilck(
		shared_ptr<ctx_c_r_forget> rctx, inode_lock_request_t& ilck)
{
	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve inode */
	get_inode_request_t req;

	req.node_id = rctx->msg.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_forget_getnode, this, rctx);

	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_forget_getnode(
		shared_ptr<ctx_c_r_forget> rctx, get_inode_request_t&& node_req)
{
	if (node_req.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::forget(rctx->msg.req_id, node_req.result));
		return;
	}

	rctx->node = node_req.node;

	/* Perform forget for this client */
	inode_remove_client_ref(rctx->node, rctx->client);

	/* Check if inode is still referenced by another link or another client */
	if (rctx->node->nlink > 0 || rctx->node->client_refs.size() > 0)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::forget(rctx->msg.req_id, err::SUCCESS));
		return;
	}

	/* Lock block allocator */
	block_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_forget_blck, this, rctx);
	lock_block_allocator(req);
}

void ctrl_ctx::cb_c_r_forget_blck(
		shared_ptr<ctx_c_r_forget> rctx, block_allocator_lock_request_t blck)
{
	rctx->blck = block_allocator_lock_witness(
			bind_front(&ctrl_ctx::unlock_block_allocator, this), blck);

	delete_inode(rctx->msg.node_id, rctx->node);
}


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::read& msg)
{
	// auto prof = profiler_get("process_client_message(read)");

	/* READ */
	/* b Lock inode */
	/* b Retrieve data map(s) */
	/* b Read data */
	/*   Unlock inode */
	/*   Assemble data */
	/*   Return data */

	// printf("read %d bytes\n", (int) msg.size);

	client_req_cnt_read++;
	// if ((client_req_cnt_read % 2000) == 0)
	// 	profiler_list(client_req_cnt_read);

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
	// auto prof = profiler_get("cb_c_r_read_ilock");

	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve data map(s) */
	get_inode_request_t req;

	req.node_id = rctx->msg.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_read_getnode, this, rctx);
	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_read_getnode(shared_ptr<ctx_c_r_read> rctx, get_inode_request_t&& ireq)
{
	// auto prof = profiler_get("cb_c_r_read_getnode");

	if (ireq.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::read(rctx->msg.req_id, ireq.result));
		return;
	}

	if (ireq.node->type != inode::TYPE_FILE)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::read(rctx->msg.req_id, err::ISDIR));
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
		auto dd_offset = b_o % data_map.block_size + (b_num / data_map.n_dd) * data_map.block_size;
		rctx->blocks.emplace_back(b_file_o - rctx->msg.offset, b_s, dd, dd_offset);
	}


	/* Allocate a buffer for the message (including data) returned to the
	 * client. It must be large enough to hold the message header. Note that an
	 * unaligned memory access will happen at some point, because the page
	 * header size may not be a multiple of the alignment size (either during
	 * sending the packet or copying, however sending may introduce an extra
	 * copy-step anyway). However memcpy has a strategy to copy unaligned bytes
	 * first and the remaining data aligned. Note also, that the data received
	 * from the dds needs to be copied eventually to strip the message headers.
	 * A more elaborate implementation could avoid this but complicates the
	 * message reception logic. Try with an extra copy step first. */
	rctx->reply_header_size = prot::client::reply::read(0, err::SUCCESS).serialize(nullptr);
	rctx->buf = buf_pool_req.get_buffer(max(
				(size_t) 4096,
				rctx->reply_header_size + rctx->read_size_total));

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
	// auto prof = profiler_get("cb_c_r_read_dd");

	/* Store result of read request and copy data if required */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		if (req.result == err::SUCCESS)
		{
			if (rctx->reply_header_size + b.offset + b.size >= rctx->buf.size())
				throw runtime_error("Internal buffer overflow");

			memcpy(
					rctx->buf.ptr() + rctx->reply_header_size + b.offset,
					req.data,
					b.size);

			buf_pool_dd_io.return_buffer(move(req._buf));
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

	/* Add message header */
	prot::client::reply::read reply(rctx->msg.req_id, err::SUCCESS);
	reply.size = rctx->read_size_total;
	auto reply_size = reply.serialize(rctx->buf.ptr()) + reply.size;

	/* Return data to client */
	send_message_to_client(rctx->client, move(rctx->buf), reply_size);

	// printf("read processing took %fms for %d bytes\n",
	// 		(get_monotonic_time() - rctx->t_start) / 1e6, (int) rctx->msg.size);
}


bool ctrl_ctx::process_client_message(
		shared_ptr<ctrl_client> client, prot::client::req::write& msg,
		dynamic_buffer&& buf)
{
	/* WRITE */
	/* b Lock inode w */
	/* b Retrieve data map(s) */
	/* b   Lock block allocator if required */
	/*     Get free blocks */
	/*     Unlock block allocator */
	/*   Update timestamps, size, and data map if required */
	/*   Split data */
	/* b Write data */
	/*   Unlock inode w */
	/*   Inform client */

	client_req_cnt_write++;

	if (msg.node_id == 0)
	{
		return send_message_to_client(
				client,
				prot::client::reply::write(msg.req_id, err::INVAL));
	}

	auto rctx = make_shared<ctx_c_r_write>(msg);
	rctx->client = client;
	rctx->t_start = get_monotonic_time();
	rctx->_buf = move(buf);

	/* Lock inode w */
	inode_lock_request_t req;

	req.node_id = rctx->msg.node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_write_ilock, this, rctx);

	lock_inode(req);

	return false;
}

void ctrl_ctx::cb_c_r_write_ilock(shared_ptr<ctx_c_r_write> rctx, inode_lock_request_t& ilck)
{
	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve data map(s) */
	get_inode_request_t req;

	req.node_id = rctx->msg.node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_c_r_write_getnode, this, rctx);
	get_inode(move(req));
}

void ctrl_ctx::cb_c_r_write_getnode(shared_ptr<ctx_c_r_write> rctx, get_inode_request_t&& ireq)
{
	if (ireq.result != err::SUCCESS)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::write(rctx->msg.req_id, ireq.result));
		return;
	}

	if (ireq.node->type != inode::TYPE_FILE)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::write(rctx->msg.req_id, err::ISDIR));
		return;
	}

	rctx->node = ireq.node;

	/* Ensure that at least one allocation can be added. Note that the next
	 * blocks might be consecutive, in which case the last allocation could be
	 * extended - however this would be more complex to rollback, hence rather
	 * keep one allocation spared on each file. */
	if (rctx->node->allocations.size() >= 240)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::write(rctx->msg.req_id, err::NOSPC));
		return;
	}


	/* Determine if new blocks need to be allocated */
	if (rctx->msg.offset > rctx->node->size + 1)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::write(rctx->msg.req_id, err::NXIO));
		return;
	}

	rctx->allocated_size = rctx->node->get_allocated_size();

	if (rctx->msg.offset + rctx->msg.size > rctx->allocated_size)
	{
		/* Lock block allocator */
		block_allocator_lock_request_t req;
		req.cb_acquired = bind_front(&ctrl_ctx::cb_c_r_write_balloc, this, rctx);

		lock_block_allocator(req);
	}
	else
	{
		cb_c_r_write_write(rctx);
	}
}

void ctrl_ctx::cb_c_r_write_balloc(shared_ptr<ctx_c_r_write> rctx, block_allocator_lock_request_t& blck)
{
	block_allocator_lock_witness blckw(bind_front(&ctrl_ctx::unlock_block_allocator, this), blck);

	/* Get free blocks */
	size_t required_blocks = (((rctx->msg.offset + rctx->msg.size) - rctx->allocated_size) +
			(data_map.allocation_granularity - 1)) / data_map.allocation_granularity;

	auto start = get_free_blocks(required_blocks);
	if (start < 0)
	{
		send_message_to_client(
				rctx->client,
				prot::client::reply::write(rctx->msg.req_id, err::NOSPC));
		return;
	}

	/* Update data map */
	rctx->node->dirty = true;

	auto alloc_start = start * data_map.allocation_granularity;
	auto alloc_size = required_blocks * data_map.allocation_granularity;
	bool merged = false;

	if (rctx->node->allocations.size() > 0)
	{
		auto& prev_alloc = rctx->node->allocations.back();

		/* Try to merge with previous allocation */
		if (prev_alloc.offset + prev_alloc.size == alloc_start)
		{
			prev_alloc.size += alloc_size;
			merged = true;
		}
	}

	if (!merged)
		rctx->node->allocations.emplace_back(alloc_start, alloc_size);

	cb_c_r_write_write(rctx);
}

void ctrl_ctx::cb_c_r_write_write(shared_ptr<ctx_c_r_write> rctx)
{
	/* Update timestamps, size */
	rctx->node->dirty = true;
	rctx->node->mtime = get_wt_now();
	rctx->node->size = max(rctx->node->size, rctx->msg.offset + rctx->msg.size);

	/* Map data to dds */
	for (auto [b_o, b_s, b_file_o] : map_file_region(*(rctx->node), rctx->msg.offset, rctx->msg.size))
	{
		auto b_num = b_o / data_map.block_size;
		auto dd = data_map.dd_rr_order[b_num % data_map.n_dd];
		auto dd_offset = b_o % data_map.block_size + (b_num / data_map.n_dd) * data_map.block_size;
		rctx->blocks.emplace_back(b_file_o - rctx->msg.offset, b_s, dd, dd_offset);
	}

	/* Write data to dds */
	for (size_t i = 0; i < rctx->blocks.size(); i++)
	{
		auto& b = rctx->blocks[i];

		dd_write_request_t req;

		req.dd = b.dd;
		req.offset = b.dd_offset;
		req.size = b.size;
		req.data = rctx->msg.data + b.offset;
		req.cb_completed = bind_front(&ctrl_ctx::cb_c_r_write_dd, this, rctx, i);

		dd_write(move(req));
	}
}

void ctrl_ctx::cb_c_r_write_dd(shared_ptr<ctx_c_r_write> rctx, size_t bi,
		dd_write_request_t&& req)
{
	/* Store result of write request */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		b.completed = true;
	}

	/* Test if all write requests have completed */
	for (auto& b : rctx->blocks)
	{
		if (!b.completed)
			return;
	}

	/* Check return codes of individual block write requests */
	for (auto& b : rctx->blocks)
	{
		if (b.result != err::SUCCESS)
		{
			send_message_to_client(
					rctx->client,
					prot::client::reply::write(rctx->msg.req_id, b.result));
			return;
		}
	}

	/* Inform client (and unlock inode w implicitely after exit) */
	send_message_to_client(rctx->client,
			prot::client::reply::write(rctx->msg.req_id, err::SUCCESS));
}


bool ctrl_ctx::send_message_to_client(shared_ptr<ctrl_client> client, const prot::msg& msg)
{
	if (client->invalid)
		return true;

	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	auto msg_len = msg.serialize(buf.ptr());
	return send_message_to_client(client, move(buf), msg_len);
}

bool ctrl_ctx::send_message_to_client(shared_ptr<ctrl_client> client,
		variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len)
{
	// auto prof = profiler_get("send_message_to_client(buf)");

	if (client->invalid)
		return true;

	if (msg_len > numeric_limits<int>::max())
		throw invalid_argument("msg_len must fit into an integer");

	auto was_empty = client->send_queue.empty();
	client->send_queue.emplace_back(move(buf), msg_len);

	if (was_empty)
	{
		if (io_uring_req_in_flight >= io_uring_max_req_in_flight)
			throw runtime_error("io uring instance full");

		auto& qmsg = client->send_queue.front();
		client->send_iovs[0].iov_base = (char*) qmsg.buf_ptr();
		client->send_iovs[0].iov_len = qmsg.msg_len;

		io_uring.queue_writev(
				client->get_fd(),
				client->send_iovs, 1, -1,
				0,
				bind_front(&ctrl_ctx::on_client_writev_finished, this, client));

		io_uring.submit();
		io_uring_req_in_flight++;
	}

	return false;
}


shared_ptr<ctrl_mp_client> ctrl_ctx::create_mp_client()
{
	uint64_t id = 1;

	/* Remove deleted mp_clients from the list in this function */
	while (id != 0)
	{
		bool used = false;

		auto i = mp_clients.end();
		if (i != mp_clients.begin())
		{
			i--;

			for (;;)
			{
				auto l = i->lock();
				if (l)
				{
					if (l->id == id)
						used = true;

					if (i == mp_clients.begin())
						break;

					i--;
				}
				else
				{
					if (i == mp_clients.begin())
					{
						mp_clients.erase(i);
						break;
					}
					else
					{
						auto tmp = i--;
						mp_clients.erase(tmp);
					}
				}
			}
		}

		if (!used)
		{
			auto mpc = make_shared<ctrl_mp_client>(id);
			mp_clients.push_back(mpc);
			return mpc;
		}

		id++;
	}

	throw runtime_error("client id space exhausted");
}

shared_ptr<ctrl_mp_client> ctrl_ctx::find_mp_client(uint64_t id)
{
	for (auto w : mp_clients)
	{
		auto l = w.lock();
		if (l && l->id == id)
			return l;
	}

	return nullptr;
}


void ctrl_ctx::main()
{
	io_uring.submit_poll(epoll.get_fd(), POLLIN,
			bind_front(&ctrl_ctx::on_epoll_ready, this));

	while (!quit_main_loop)
	{
		io_uring.process_requests(true);

		if (quit_requested)
			perform_shutdown();
	}
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


void ctrl_ctx::lock_block_allocator(block_allocator_lock_request_t& req)
{
	if (!block_allocator.locked)
	{
		block_allocator.locked = true;

		/* NOTE: It is very important that unlock_block_allocator can be called
		 * from this callback.
		 *
		 * NOTE: cb_aquired might reference a shared_ptr (partially evaluated
		 * function) to an object, which might contain a copy of req. This would
		 * lead to a depenency loop of the shared_ptr. To prevent this and as
		 * cb_acquired will not be needed anymore after calling it here, pass a
		 * copy of req to cb_acquired which has cb_acquired set to nullptr. */
		block_allocator_lock_request_t r2(req);
		r2.cb_acquired = nullptr;

		auto cb = req.cb_acquired;
		cb(r2);
	}
	else
	{
		block_allocator.lock_reqs.push_back(req);
	}
}

void ctrl_ctx::unlock_block_allocator(block_allocator_lock_request_t& req)
{
	if (!block_allocator.locked)
		throw invalid_argument("Lock not held");

	block_allocator.locked = false;

	/* Process pending lock requests; Note that the cb_acquired function
	 * supplied by the lock requester might call unlock_block_allocator, too.
	 * This leads to recursive invocation of this function. The innermost
	 * invocation will run its loop as long as possible, and than the outer
	 * invocations will continue. Hence it is important the check the state of
	 * the lock after each run and take into account that the lock queue might
	 * change. */
	while (!block_allocator.locked &&
			block_allocator.lock_reqs.size())
	{
		block_allocator.locked = true;

		auto r = block_allocator.lock_reqs.front();
		block_allocator.lock_reqs.pop_front();

		auto cb = r.cb_acquired;
		r.cb_acquired = nullptr;
		cb(r);
	}
}


ssize_t ctrl_ctx::get_free_blocks(size_t count)
{
	auto total_blocks = data_map.total_data_size / data_map.allocation_granularity;

	/* The last used block is i + count - 1 */
	for (size_t i = 0; i <= total_blocks - count; i++)
	{
		bool found = true;

		for (size_t j = 0; j < count; j++)
		{
			auto pos = i + j;
			if (block_allocator.bitmap[pos / 8] & (1 << (pos % 8)))
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			block_allocator.dirty = true;

			for (size_t j = 0; j < count; j++)
			{
				auto pos = i + j;
				block_allocator.bitmap[pos / 8] |= (1 << (pos % 8));
			}

			block_allocator.allocated_count += count;
			return i;
		}
	}

	return -1;
}

void ctrl_ctx::unallocate_blocks(size_t start, size_t count)
{
	auto total_blocks = data_map.total_data_size / data_map.allocation_granularity;

	if (start + count > total_blocks)
		throw invalid_argument("start + count out of range");


	for (size_t i = start; i < start + count; i++)
	{
		auto pos = i / 8;
		uint8_t mask = (1 << (i % 8));

		if ((block_allocator.bitmap[pos] & mask) == 0)
			throw runtime_error("attempted to unallocate block which is not allocated");

		block_allocator.dirty = true;
		block_allocator.bitmap[pos] &= ~mask;
		block_allocator.allocated_count--;
	}
}


void ctrl_ctx::get_inode(get_inode_request_t&& req)
{
	if (req.node_id >= data_map.total_inode_count || req.node_id == 0)
		throw invalid_argument("Inode id out of range");

	/* Check if inode exists, i.e. is allocated */
	/* This function needs to be called with the inode locked. Hence we can
	 * access the inode allocator without a lock on the node allocator itself,
	 * because this bit in the node allocator cannot be changed. */
	auto alloc_node_id = req.node_id - 1;
	if ((inode_directory.allocator_bitmap[alloc_node_id / 8] & (1 << (alloc_node_id % 8))) == 0)
	{
		req.result = err::NOENT;

		/* Same problem as in lock_inode */
		auto cb = req.cb_finished;
		req.cb_finished = nullptr;
		cb(move(req));
		return;
	}

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
	auto rctx = make_shared<ctx_m_g_inode>(move(req));

	/* Compute position on disk and issue IO request on first dd */
	dd_read_request_t dd_req;

	dd_req.dd = &dds.front();
	dd_req.offset = dd_req.dd->inode_directory_offset + (rctx->req.node_id - 1) * 4096;
	dd_req.size = 4096;
	dd_req.cb_completed = bind_front(&ctrl_ctx::cb_m_g_inode, this, rctx);

	dd_read(move(dd_req));
}

void ctrl_ctx::cb_m_g_inode(shared_ptr<ctx_m_g_inode> rctx, dd_read_request_t&& dd_req)
{
	if (dd_req.result != err::SUCCESS)
	{
		rctx->req.result = err::IO;
		auto cb = rctx->req.cb_finished;
		rctx->req.cb_finished = nullptr;
		cb(move(rctx->req));
		return;
	}

	/* Parse inode */
	auto node = make_shared<inode>();
	node->parse(dd_req.data);

	/* Note that it is perfectly fine that this insertion does not happen - in
	 * this case another concurrent read-process (the inode is under
	 * non-exclusive lock if this is a read-request) did fetch the inode
	 * already.  Simply return that copy, then. */
	auto [i, inserted] = inode_directory.cached_inodes.insert({rctx->req.node_id, node});

	rctx->req.result = err::SUCCESS;
	rctx->req.node = i->second;
	rctx->req.was_in_cache = !inserted;

	auto cb = rctx->req.cb_finished;
	rctx->req.cb_finished = nullptr;
	cb(move(rctx->req));
}


void ctrl_ctx::mark_inode_allocated(unsigned long node_id)
{
	if (node_id >= data_map.total_inode_count || node_id == 0)
		throw invalid_argument("Inode id out of range");

	node_id--;

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

	node_id--;

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
	for (unsigned long i = 0; i < data_map.total_inode_count; i++)
	{
		auto off = i / 8;
		auto mask = 1 << (i % 8);

		if (!(inode_directory.allocator_bitmap[off] & mask))
			return i + 1;
	}

	return -1;
}


void ctrl_ctx::inode_add_client_ref(shared_ptr<inode> node, shared_ptr<ctrl_client> client)
{
	if (client->invalid)
		return;

	/* Check if client is on list and cleanup destroyed clients */
	bool found = false;

	auto mp_client = client->mp_client;
	if (!mp_client)
		throw runtime_error("client without mp_client performs IO");

	vector<decltype(node->client_refs)::iterator> to_delete;

	for (auto i = node->client_refs.begin(); i != node->client_refs.end(); i++)
	{
		auto lo = i->lock();
		if (lo)
		{
			if (lo == mp_client)
				found = true;
		}
		else
		{
			to_delete.push_back(i);
		}
	}

	for (auto j = to_delete.rbegin(); j != to_delete.rend(); j++)
		node->client_refs.erase(*j);

	if (!found)
		node->client_refs.push_back(mp_client);
}

void ctrl_ctx::inode_remove_client_ref(shared_ptr<inode> node, shared_ptr<ctrl_client> client)
{
	shared_ptr<ctrl_mp_client> mp_client;

	if (client)
	{
		mp_client = client->mp_client;
		if (!mp_client)
			throw runtime_error("client without mp_client performs IO");
	}

	/* Remove client if it is on the list and cleanup destroyed clients */
	vector<decltype(node->client_refs)::iterator> to_delete;

	for (auto i = node->client_refs.begin(); i != node->client_refs.end(); i++)
	{
		auto lo = i->lock();
		if (!lo || (mp_client && lo == mp_client))
			to_delete.push_back(i);
	}

	for (auto j = to_delete.rbegin(); j != to_delete.rend(); j++)
		node->client_refs.erase(*j);
}

void ctrl_ctx::delete_inode(unsigned long node_id, shared_ptr<inode> node)
{
	/* Unallocate ranges */
	while (node->allocations.size() > 0)
	{
		auto& a = node->allocations.back();

		if (
				a.offset % data_map.allocation_granularity != 0 ||
				a.size % data_map.allocation_granularity != 0)
		{
			throw runtime_error("allocation's offset or size is not a multiple "
					"of the allocation granularity");
		}

		unallocate_blocks(
				a.offset / data_map.allocation_granularity,
				a.size / data_map.allocation_granularity);

		node->allocations.pop_back();
	}

	/* Unallocate inode */
	mark_inode_unallocated(node_id);

	/* Evict cache entry */
	auto i = inode_directory.cached_inodes.find(node_id);
	if (i != inode_directory.cached_inodes.end())
		inode_directory.cached_inodes.erase(i);

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


/* Only to be used during initialization, before the main loop is running */
fixed_buffer ctrl_ctx::dd_read_sync_startup(
		ctrl_dd* dd, size_t offset, size_t size)
{
	fixed_buffer buf(size);

	for (size_t pos = 0; pos < size; pos += 1024 * 1024)
	{
		size_t to_read = min(1024 * 1024UL, size - pos);

		prot::dd::req::read req;
		req.request_id = get_request_id();
		req.offset = offset + pos;
		req.length = to_read;

		send_stream_msg(dd->get_fd(), req);
		auto reply = receive_stream_msg<
			prot::dd::reply::read,
			prot::dd::reply::parse>
				(dd->get_fd(), 30000);

		if (
				reply->request_id != req.request_id ||
				reply->res != err::SUCCESS ||
				reply->data_length != to_read)
		{
			throw runtime_error("Failed to read from dd during startup");
		}

		memcpy(buf.ptr(), reply->data, reply->data_length);
	}

	return buf;
}


void ctrl_ctx::store_metadata()
{
	store_allocation_bitmap();
	store_inode_allocator_bitmap();
	store_inodes();
}

void ctrl_ctx::store_allocation_bitmap()
{
	if (!block_allocator.dirty)
		return;

	/* b Lock block allocator */
	/* b Write allocation bitmap to all dds */
	/*   Unlock block allocator */

	auto rctx = make_shared<ctx_m_s_balloc>();

	/* Lock block allocator */
	block_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_m_s_balloc_lck, this, rctx);

	lock_block_allocator(req);
}

void ctrl_ctx::cb_m_s_balloc_lck(shared_ptr<ctx_m_s_balloc> rctx,
		block_allocator_lock_request_t& blck)
{
	rctx->blck = block_allocator_lock_witness(bind_front(&ctrl_ctx::unlock_block_allocator, this), blck);

	/* Generate write requests */
	const size_t block_size = 1024 * 1024;
	for (size_t pos = 0; pos < data_map.allocation_bitmap_size; pos += block_size)
	{
		auto to_write = min(block_size, data_map.allocation_bitmap_size - pos);

		for (auto& dd : dds)
		{
			rctx->blocks.emplace_back(
					dd.allocation_bitmap_offset + pos,
					to_write,
					(char*) block_allocator.bitmap + pos,
					&dd);
		}
	}

	/* Write to all dds */
	for (size_t i = 0; i < rctx->blocks.size(); i++)
	{
		auto& b = rctx->blocks[i];

		dd_write_request_t req;

		req.dd = b.dd;
		req.offset = b.offset;
		req.size = b.size;
		req.data = b.data;
		req.cb_completed = bind_front(&ctrl_ctx::cb_m_s_balloc_dd, this, rctx, i);

		dd_write(move(req));
	}
}

void ctrl_ctx::cb_m_s_balloc_dd(shared_ptr<ctx_m_s_balloc> rctx, size_t bi,
		dd_write_request_t&& req)
{
	/* Store result of write request */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		b.completed = true;
	}

	/* Test if all write requests have completed */
	for (auto& b : rctx->blocks)
	{
		if (!b.completed)
			return;
	}

	/* Check return codes of individual block write requests */
	bool error = false;
	for (auto& b : rctx->blocks)
	{
		if (b.result != err::SUCCESS)
		{
			error = true;
			fprintf(stderr, "Failed to write allocation bitmap to dd %u.\n",
					(unsigned) b.dd->id);
		}
	}

	if (error)
		throw runtime_error("Failed to write allocation bitmap to disk");

	/* Reset dirty flags */
	block_allocator.dirty = false;
}


void ctrl_ctx::store_inode_allocator_bitmap()
{
	if (!inode_directory.allocator_dirty)
		return;

	/* b Lock inode allocator */
	/* b Write allocation bitmap to all dds */
	/*   Unlock inode allocator */

	auto rctx = make_shared<ctx_m_s_ialloc>();

	/* Lock inode allocator */
	inode_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_m_s_ialloc_lck, this, rctx);

	lock_inode_allocator(req);
}

void ctrl_ctx::cb_m_s_ialloc_lck(shared_ptr<ctx_m_s_ialloc> rctx,
		inode_allocator_lock_request_t& ialck)
{
	rctx->ialck = inode_allocator_lock_witness(bind_front(&ctrl_ctx::unlock_inode_allocator, this), ialck);

	/* Generate write requests */
	const size_t block_size = 1024 * 1024;
	const size_t bitmap_size = (data_map.total_inode_count + 7) / 8;

	for (size_t pos = 0; pos < bitmap_size; pos += block_size)
	{
		auto to_write = min(block_size, bitmap_size - pos);

		for (auto& dd : dds)
		{
			rctx->blocks.emplace_back(
					dd.inode_bitmap_offset + pos,
					to_write,
					(char*) inode_directory.allocator_bitmap + pos,
					&dd);
		}
	}

	/* Write to all dds */
	for (size_t i = 0; i < rctx->blocks.size(); i++)
	{
		auto& b = rctx->blocks[i];

		dd_write_request_t req;

		req.dd = b.dd;
		req.offset = b.offset;
		req.size = b.size;
		req.data = b.data;
		req.cb_completed = bind_front(&ctrl_ctx::cb_m_s_ialloc_dd, this, rctx, i);

		dd_write(move(req));
	}
}

void ctrl_ctx::cb_m_s_ialloc_dd(shared_ptr<ctx_m_s_ialloc> rctx, size_t bi,
		dd_write_request_t&& req)
{
	/* Store result of write request */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		b.completed = true;
	}

	/* Test if all write requests have completed */
	for (auto& b : rctx->blocks)
	{
		if (!b.completed)
			return;
	}

	/* Check return codes of individual block write requests */
	bool error = false;
	for (auto& b : rctx->blocks)
	{
		if (b.result != err::SUCCESS)
		{
			error = true;
			fprintf(stderr, "Failed to write inode allocator bitmap to dd %u.\n",
					(unsigned) b.dd->id);
		}
	}

	if (error)
		throw runtime_error("Failed to write inode allocator bitmap to disk");

	/* Reset dirty flag */
	inode_directory.allocator_dirty = false;
}

void ctrl_ctx::store_inodes()
{
	/* Find all inodes that need to be stored */
	auto rctx = make_shared<ctx_m_s_inodes>();

	for (auto [node_id, node] : inode_directory.cached_inodes)
	{
		if (node->dirty)
			rctx->nodes_to_store.emplace_back(node_id, node);
	}

	/* Submit first node if any */
	if (rctx->nodes_to_store.size() > 0)
	{
		for (auto& dd : dds)
			rctx->blocks.emplace_back(&dd);

		store_inodes_node(rctx);
	}
}

void ctrl_ctx::store_inodes_node(shared_ptr<ctx_m_s_inodes> rctx)
{
	/* Lock inode */
	inode_lock_request_t req;
	req.node_id = rctx->nodes_to_store.back().node_id;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_m_s_inodes_ilock, this, rctx);

	lock_inode(req);
}

void ctrl_ctx::cb_m_s_inodes_ilock(shared_ptr<ctx_m_s_inodes> rctx,
		inode_lock_request_t& ilck)
{
	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	auto& nts = rctx->nodes_to_store.back();

	/* Check if the node is still cached, otherwise proceed with the next
	 * node.
	 * NOTE: This might lead to a large recursion depth... */
	if (inode_directory.cached_inodes.find(nts.node_id) == inode_directory.cached_inodes.end())
	{
		rctx->nodes_to_store.pop_back();
		rctx->ilck = inode_lock_witness();
		store_inodes_node(rctx);
		return;
	}

	/* Calculate position, serialize inodes, reset dirty flag, and unlock
	 * inode */
	auto pos = (nts.node_id - 1) * 4096;
	nts.node->serialize(rctx->buf.ptr());

	nts.node->dirty = false;

	 /* Calculate positions on dds and submit io requests */
	for (size_t i = 0; i < rctx->blocks.size(); i++)
	{
		auto& b = rctx->blocks[i];
		b.completed = false;
		b.result = -1;

		dd_write_request_t req;

		req.dd = b.dd;
		req.offset = b.dd->inode_directory_offset + pos;
		req.size = 4096;
		req.data = rctx->buf.ptr();
		req.cb_completed = bind_front(&ctrl_ctx::cb_m_s_inodes_dd, this, rctx, i);

		dd_write(move(req));
	}
}

void ctrl_ctx::cb_m_s_inodes_dd(shared_ptr<ctx_m_s_inodes> rctx, size_t bi, dd_write_request_t&& req)
{
	/* Store result of write request */
	{
		auto& b = rctx->blocks[bi];
		b.result = req.result;
		b.completed = true;
	}

	/* Test if all write requests have completed */
	for (auto& b : rctx->blocks)
	{
		if (!b.completed)
			return;
	}

	/* Check return codes of individual write requests */
	for (auto& b : rctx->blocks)
	{
		if (b.result != err::SUCCESS)
			throw runtime_error("Failed to write inode to disk");
	}

	/* Reset dirty flag of inode and unlock inode */
	rctx->nodes_to_store.back().node->dirty = false;
	rctx->nodes_to_store.pop_back();
	rctx->ilck = inode_lock_witness();

	/* Continue with next inode if any */
	if (rctx->nodes_to_store.size() > 0)
		store_inodes_node(rctx);
}


void ctrl_ctx::perform_shutdown()
{
	/* SHUTDOWN PROCEDURE */
	/* 0 Stop accepting new clients */
	/* 0 Stop answering new client requests */
	/* 0 Stop background tasks */
	/* 1 Wait for all clients to become idle and for background tasks to stop */
	/* 1 Remove all clients */
	/* 2 Save metadata */
	/* 2 Stop main loop */

	switch (shutdown_state)
	{
	case 0:
		initiate_shutdown();
		break;

	case 1:
		shutdown_wait_for_operations();
		break;

	case 2:
		shutdown_wait_metadata();
		break;

	default:
		throw runtime_error("invalid shutdown state");
	}
}

void ctrl_ctx::initiate_shutdown()
{
	printf("Shutdown procedure initiated.\n");

	/* Stop accepting new clients */
	stop_accepting_new_clients = true;

	/* Stop answering new client requests */
	stop_accepting_client_requests = true;

	/* Stop background tasks */
	background_job_enabled = false;
	bg_tfd.stop();

	shutdown_state = 1;

	printf("  waiting for operations to complete...\n");
	shutdown_wait_for_operations();
}

void ctrl_ctx::shutdown_wait_for_operations()
{
	/* Check for all kinds of pending requests - these are the only asynchronous
	 * operations that can be in progress. */

	/* dd IO requests */
	for (auto& dd : dds)
	{
		if (dd.read_reqs.size() > 0 || dd.write_reqs.size() > 0)
			return;
	}

	/* inode lock requests */
	/* Note that a held lock is no reasion for an entity to block - hence they
	 * do not need to be checked here. */
	for (auto& [node_id,nl] : inode_directory.node_locks)
	{
		if (nl.reqs.size() > 0)
			return;
	}

	/* inode allocator lock requests */
	if (inode_directory.allocator_lock_reqs.size() > 0)
		return;

	/* block allocator lock requests */
	if (block_allocator.lock_reqs.size() > 0)
		return;

	/* Clients with outgoing messages in in flight
	 * Note that invalid clients with a non-empty send-queue that still exist
	 * will be removed shortly after, i.e. when the last message in flight was
	 * successfully sent or sending aborted with an error. */
	for (auto c : clients)
	{
		if (c->send_queue.size() > 0)
			return;
	}

	/* io uring requests in flight (should be caught be the other request types
	 * though, hence the exception) */
	if (io_uring_req_in_flight != 0)
		throw runtime_error("io uring request in flight during shutdown");

	/* Remove all clients */
	while (clients.size() > 0)
		remove_client(clients.begin());

	/* Initiate final metadata saving */
	store_metadata();

	shutdown_state = 2;

	printf("  waiting for metadata to be saved...\n");
	shutdown_wait_metadata();
}

void ctrl_ctx::shutdown_wait_metadata()
{
	/* Wait for metadata to be saved; this can only be delayed by dd IO */
	for (auto& dd : dds)
	{
		if (dd.read_reqs.size() > 0 || dd.write_reqs.size() > 0)
			return;
	}

	/* Stop the main loop */
	printf("  stopping.\n");
	quit_main_loop = true;
}


void ctrl_ctx::purge_unreferenced_inodes()
{
	if (purge_unreferenced_inodes_witness.lock())
		return;

	/* Find potential inodes to purge - will be examined further when locked */
	auto rctx = make_shared<ctx_m_purge_inodes>();
	purge_unreferenced_inodes_witness = rctx;

	for (auto [id, node] : inode_directory.cached_inodes)
	{
		if (node->nlink == 0)
			rctx->to_examine.push_back(id);
	}

	if (!purge_unreferenced_inodes_all_scanned)
	{
		for (unsigned long i = 0; i < data_map.total_inode_count; i++)
		{
			if ((inode_directory.allocator_bitmap[i / 8] & (1 << (i % 8))) != 0)
				rctx->to_examine.push_back(i + 1);
		}

		purge_unreferenced_inodes_all_scanned = true;
	}

	/* For each inode, the following locks are required: inode allocator, inode,
	 * block allocator. */
	purge_inodes_next(rctx);
}

void ctrl_ctx::purge_inodes_next(shared_ptr<ctx_m_purge_inodes> rctx)
{
	rctx->ialck = inode_allocator_lock_witness();
	rctx->ilck = inode_lock_witness();
	rctx->blck = block_allocator_lock_witness();
	rctx->node = nullptr;

	if (rctx->to_examine.size() > 0)
	{
		rctx->node_id = rctx->to_examine.back();
		rctx->to_examine.pop_back();

		inode_allocator_lock_request_t req;
		req.cb_acquired = bind_front(&ctrl_ctx::cb_m_purge_inodes_ialck, this, rctx);

		lock_inode_allocator(req);
	}
}

void ctrl_ctx::cb_m_purge_inodes_ialck(
		shared_ptr<ctx_m_purge_inodes> rctx, inode_allocator_lock_request_t& ialck)
{
	rctx->ialck = inode_allocator_lock_witness(
			bind_front(&ctrl_ctx::unlock_inode_allocator, this), ialck);

	/* Lock inode w */
	inode_lock_request_t req;

	req.node_id = rctx->node_id;
	req.write = true;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_m_purge_inodes_ilck, this, rctx);

	lock_inode(req);
}

void ctrl_ctx::cb_m_purge_inodes_ilck(
		shared_ptr<ctx_m_purge_inodes> rctx, inode_lock_request_t& ilck)
{
	rctx->ilck = inode_lock_witness(bind_front(&ctrl_ctx::unlock_inode, this), ilck);

	/* Retrieve inode */
	get_inode_request_t req;

	req.node_id = rctx->node_id;
	req.cb_finished = bind_front(&ctrl_ctx::cb_m_purge_inodes_getnode, this, rctx);

	get_inode(move(req));
}

void ctrl_ctx::cb_m_purge_inodes_getnode(
		shared_ptr<ctx_m_purge_inodes> rctx, get_inode_request_t&& node_req)
{
	/* Cleanup leftover references of disconnected clients */
	if (node_req.result == err::SUCCESS)
		inode_remove_client_ref(node_req.node, nullptr);

	if (node_req.result != err::SUCCESS ||
			node_req.node->nlink > 0 || node_req.node->client_refs.size() > 0)
	{
		/* Evict inode if it was not in the cache before and is not referenced
		 * by a client. This is possible because we own a write-lock on it. */
		if (!node_req.was_in_cache && node_req.node->client_refs.empty())
		{
			auto i = inode_directory.cached_inodes.find(rctx->node_id);
			if (i != inode_directory.cached_inodes.end())
				inode_directory.cached_inodes.erase(i);
		}

		/* Continue with next node */
		purge_inodes_next(rctx);
		return;
	}

	rctx->node = node_req.node;

	/* Lock block allocator */
	block_allocator_lock_request_t req;
	req.cb_acquired = bind_front(&ctrl_ctx::cb_m_purge_inodes_blck, this, rctx);
	lock_block_allocator(req);
}

void ctrl_ctx::cb_m_purge_inodes_blck(
		shared_ptr<ctx_m_purge_inodes> rctx, block_allocator_lock_request_t blck)
{
	rctx->blck = block_allocator_lock_witness(
			bind_front(&ctrl_ctx::unlock_block_allocator, this), blck);

	delete_inode(rctx->node_id, rctx->node);
	purge_inodes_next(rctx);
}
