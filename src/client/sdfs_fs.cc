#include <new>
#include "common/utils.h"
#include "sdfs_fs_internal.h"
#include "common/error_codes.h"

using namespace std;


size_t allocator_t::count_allocated()
{
	size_t cnt = 0;

	for (size_t i = 0; i < buf.get_size(); i++)
	{
		for (int j = 0; j < 8; j++)
		{
			if (buf.ptr()[i] & (1 << j))
				cnt++;
		}
	}

	return cnt;
}

FSClient::FSClient(const std::vector<std::string>& srv_portals)
	: dsc(srv_portals)
{
	io_promise iop;

	/* Get raw size */
	sdfs::ds_attr_t ds_attr;
	dsc.getattr(&ds_attr, cb_io_promise, &iop);
	if (iop.wait() != err::SUCCESS)
		throw system_error(EIO, generic_category());

	raw_size = ds_attr.size;

	if (raw_size < 4096)
		throw runtime_error("raw size of block storage too small");

	/* Read superblock */
	char buf[4096];
	dsc.read(buf, raw_size - 4096, 4096, cb_io_promise, &iop);
	if (iop.wait() != err::SUCCESS)
		throw system_error(EIO, generic_category());

	sb = parse_superblock(raw_size, buf);
}

FSClient::~FSClient()
{
}


request_t* FSClient::add_request()
{
	decltype(requests)::iterator i;
	{
		unique_lock lk(m_requests);
		requests.emplace_front();
		i = requests.begin();
	}

	auto& req = *i;
	req.i_list = i;
	req.fsc = this;
	req.handle = next_handle.fetch_add(1, memory_order_acq_rel);

	return &req;
}

void FSClient::remove_request(request_t* req)
{
	unique_lock lk(m_requests);
	requests.erase(req->i_list);
}

void FSClient::finish_request(request_t* req, int res)
{
	req->cb_finished(req->handle, res, req->cb_finished_arg);

	unique_lock lk(m_requests);
	requests.erase(req->i_list);
}


void FSClient::read_block_allocator(allocator_t& alloc, cb_dsio_t cb, request_t* req)
{
	auto p = new cb_dsio_req_patch();

	try
	{
		p->req = req;
		p->cb = cb;

		alloc.buf = fixed_buffer(sb.block_allocator_size);
		dsc.read(alloc.buf.ptr(), sb.block_allocator_offset, sb.block_allocator_size,
				cb_allocator, p);
	}
	catch (...)
	{
		delete p;
		throw;
	}
}

void FSClient::read_inode_allocator(allocator_t& alloc, cb_dsio_t cb, request_t* req)
{
	auto p = new cb_dsio_req_patch();

	try
	{
		p->req = req;
		p->cb = cb;

		alloc.buf = fixed_buffer(sb.inode_allocator_size);
		dsc.read(alloc.buf.ptr(), sb.inode_allocator_offset, sb.inode_allocator_size,
				cb_allocator, p);
	}
	catch (...)
	{
		delete p;
		throw;
	}
}

void FSClient::cb_allocator(size_t handle, int res, void* arg)
{
	auto p = reinterpret_cast<cb_dsio_req_patch*>(arg);
	auto req = p->req;
	auto cb = p->cb;
	delete p;

	if (res != err::SUCCESS)
		req->io_error = true;

	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	cb(req);
}


void FSClient::read_inode(unsigned long node_id, inode_t& node,
		cb_dsio_t cb, request_t* req)
{
	if (node_id == 0 || node_id >= sb.inode_count)
	{
		req->io_error = true;

		req->finished_reqs.fetch_add(1, memory_order_acq_rel);
		cb(req);
		return;
	}

	auto c = new cb_inode_ctx();

	try
	{
		c->req = req;
		c->cb = cb;
		c->node_id = node_id;
		c->node = &node;

		dsc.read(c->buf, sb.inode_directory_offset + node_id * 4096, 4096,
				cb_read_inode, c);
	}
	catch (...)
	{
		delete c;
		throw;
	}
}

void FSClient::cb_read_inode(size_t handle, int res, void* arg)
{
	auto c = reinterpret_cast<cb_inode_ctx*>(arg);
	auto req = c->req;
	auto cb = c->cb;

	try
	{
		if (res == err::SUCCESS)
		{
			c->node->parse(c->buf);
			c->node->node_id = c->node_id;
		}
		else
		{
			req->io_error = true;
		}

		delete c;
	}
	catch (...)
	{
		delete c;
		throw;
	}

	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	cb(req);
}


void FSClient::write_block_allocator(allocator_t& alloc, cb_dsio_t cb, request_t* req)
{
	if (!alloc.buf || alloc.buf.get_size() != sb.block_allocator_size)
		throw invalid_argument("Given allocator has invalid buffer");

	auto p = new cb_dsio_req_patch();

	try
	{
		p->req = req;
		p->cb = cb;

		dsc.write(alloc.buf.ptr(), sb.block_allocator_offset, sb.block_allocator_size,
				cb_allocator, p);
	}
	catch (...)
	{
		delete p;
		throw;
	}
}


void FSClient::write_inode_allocator(allocator_t& alloc, cb_dsio_t cb, request_t* req)
{
	if (!alloc.buf || alloc.buf.get_size() != sb.inode_allocator_size)
		throw invalid_argument("Given allocator has invalid buffer");

	auto p = new cb_dsio_req_patch();

	try
	{
		p->req = req;
		p->cb = cb;

		dsc.write(alloc.buf.ptr(), sb.inode_allocator_offset, sb.inode_allocator_size,
				cb_allocator, p);
	}
	catch (...)
	{
		delete p;
		throw;
	}
}


void FSClient::write_inode(unsigned long node_id, const inode_t& node,
		cb_dsio_t cb, request_t* req)
{
	if (node_id == 0 || node_id >= sb.inode_count)
	{
		req->io_error = true;

		req->finished_reqs.fetch_add(1, memory_order_acq_rel);
		cb(req);
		return;
	}

	auto c = new cb_inode_ctx();

	try
	{
		c->req = req;
		c->cb = cb;

		/* Serialize inode */
		node.serialize(c->buf);

		/* Write inode */
		dsc.write(c->buf, sb.inode_directory_offset + node_id * 4096, 4096,
				cb_write_inode, c);
	}
	catch (...)
	{
		delete c;
		throw;
	}
}

void FSClient::cb_write_inode(size_t handle, int res, void* arg)
{
	auto c = reinterpret_cast<cb_inode_ctx*>(arg);
	auto req = c->req;
	auto cb = c->cb;
	delete c;

	if (res != err::SUCCESS)
		req->io_error = true;

	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	cb(req);
}


void FSClient::allocate_inode(unsigned long& node_id, cb_err_t cb, request_t* req)
{
	cb_allocate_inode_ctx c;
	c.cb = cb;
	c.node_id = &node_id;

	read_inode_allocator(req->inode_allocator,
			bind_front(&FSClient::cb_allocate_inode, this, c), req);
}

void FSClient::cb_allocate_inode(cb_allocate_inode_ctx c, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(err::IO, req);
		return;
	}

	/* Find free inode */
	for (unsigned long i = 1; i < sb.inode_count; i++)
	{
		if (req->inode_allocator.is_free(i))
		{
			req->inode_allocator.mark_allocated(i);
			c.new_id = i;

			break;
		}
	}

	if (c.new_id == 0)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(err::NOSPC, req);
		return;
	}

	/* Write inode allocator */
	write_inode_allocator(req->inode_allocator,
			bind_front(&FSClient::cb_allocate_inode2, this, c), req);
}

void FSClient::cb_allocate_inode2(cb_allocate_inode_ctx c, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (!req->io_error)
		*c.node_id = c.new_id;

	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	c.cb(req->io_error ? err::IO : err::SUCCESS, req);
}


void FSClient::free_inode(unsigned long node_id, cb_dsio_t cb, request_t* req)
{
	/* Check if inode number is in range */
	if (node_id == 0 || node_id >= sb.inode_count)
	{
		req->io_error = true;

		req->finished_reqs.fetch_add(3, memory_order_acq_rel);
		cb(req);
		return;
	}

	/* Read inode allocator */
	cb_free_inode_ctx c;
	c.cb = cb;
	c.node_id = node_id;

	read_inode_allocator(req->inode_allocator,
			bind_front(&FSClient::cb_free_inode, this, c), req);
}

void FSClient::cb_free_inode(cb_free_inode_ctx c, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(req);
		return;
	}

	/* Mark inode free */
	req->inode_allocator.mark_free(c.node_id);

	/* Write inode allocator */
	write_inode_allocator(req->inode_allocator,
			bind_front(&FSClient::cb_free_inode2, this, c), req);
}

void FSClient::cb_free_inode2(cb_free_inode_ctx c, request_t* req)
{
	req->finished_reqs.fetch_add(1, memory_order_acq_rel);

	c.cb(req);
	return;
}


void FSClient::free_blocks_of_file(inode_t& node, cb_dsio_t cb, request_t* req)
{
	cb_block_allocation_ctx c;
	c.cb = cb;
	c.node = &node;

	if (c.node->allocations.empty())
	{
		req->finished_reqs.fetch_add(3, memory_order_acq_rel);
		c.cb(req);
		return;
	}

	read_block_allocator(req->block_allocator,
			bind_front(&FSClient::cb_free_blocks_of_file, this, c), req);
}

void FSClient::cb_free_blocks_of_file(cb_block_allocation_ctx c, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(req);
		return;
	}

	/* Mark allocations free */
	for (auto& a : c.node->allocations)
	{
		for (
				size_t i = a.offset / (1024 * 1024);
				i < (a.offset + a.size) / (1024 * 1024);
				i++)
		{
			req->block_allocator.mark_free(i);
		}
	}

	/* Write block allocator */
	write_block_allocator(req->block_allocator,
			bind_front(&FSClient::cb_free_blocks_of_file2, this, c), req);
}

void FSClient::cb_free_blocks_of_file2(cb_block_allocation_ctx c, request_t* req)
{
	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	c.cb(req);
}


void FSClient::allocate_blocks_for_file(inode_t& node, size_t to_allocate,
		cb_dsio_t cb, request_t* req)
{
	cb_block_allocation_ctx c;
	c.cb = cb;
	c.node = &node;
	c.to_allocate = to_allocate;

	/* Load block allocator */
	read_block_allocator(req->block_allocator,
			bind_front(&FSClient::cb_allocate_blocks_for_file, this, c), req);
}

void FSClient::cb_allocate_blocks_for_file(cb_block_allocation_ctx c, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(req);
		return;
	}

	auto node = c.node;
	ssize_t to_allocate = c.to_allocate;

	/* Overflow (second clause: potentially later overflow) */
	if (
			to_allocate <= 0 ||
			to_allocate > numeric_limits<ssize_t>::max() - 1024 * 1024 * 1024L)
	{
		req->io_error = true;
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		c.cb(req);
		return;
	}


	/* Ensure allocated size alignment based on file size to limit the rate of
	 * required allocation calls */
	auto new_size = node->get_allocated_size() + to_allocate;
	size_t granularity = 1;

	if (new_size > 1024 * (1024 * 1024UL))
		granularity = 1024 * (1024 * 1024UL);
	else if (new_size > 100 * (1024 * 1024UL))
		granularity = 100 * (1024 * 1024UL);
	else if (new_size > 10 * (1024 * 1024UL))
		granularity = 10 * (1024 * 1024UL);

	auto min_new_size = ((new_size + granularity - 1) / granularity) * granularity;
	to_allocate += min_new_size - new_size;


	/* Allocate blocks */
	/* Begin search at the beginning where spinning disks are fastest */
	size_t i_block = 0;

	constexpr size_t block_size = 1024 * 1024;

	while (i_block < sb.block_count && to_allocate > 0)
	{
		if (req->block_allocator.is_free(i_block))
		{
			req->block_allocator.mark_allocated(i_block);

			/* Try to merge with last allocation */
			auto b_offset = i_block * block_size;
			if (node->allocations.size() &&
					node->allocations.back().offset + node->allocations.back().size == b_offset)
			{
				node->allocations.back().size += block_size;
			}
			else
			{
				/* Inode already full */
				if (node->allocations.size() >= 240)
					break;

				node->allocations.emplace_back(b_offset, block_size);
			}

			to_allocate -= block_size;
		}

		i_block++;
	}

	if (to_allocate > 0)
	{
		req->io_error = true;
		req->err_no_spc = true;
		c.cb(req);
		return;
	}

	/* Write block allocator */
	write_block_allocator(req->block_allocator,
			bind_front(&FSClient::cb_allocate_blocks_for_file2, this, c), req);
}

void FSClient::cb_allocate_blocks_for_file2(cb_block_allocation_ctx c, request_t* req)
{
	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	c.cb(req);
}


vector<tuple<size_t, size_t, size_t>> FSClient::map_chunk(
		const inode_t& node, size_t offset, size_t size)
{
	vector<tuple<size_t, size_t, size_t>> ret;

	size_t ptr = 0;
	size_t buf_ptr = 0;
	auto chunk_end = offset + size;

	for (const auto& a : node.allocations)
	{
		/* Check for overlap */
		auto a_end = ptr + a.size;

		if (a_end <= offset)
		{
			ptr += a.size;
			continue;
		}

		if (ptr >= chunk_end)
			break;

		/* Start of overlap relative to allocation */
		size_t off_alloc = ptr >= offset ? 0 : offset - ptr;

		/* Size of overlap */
		size_t common_start = max(ptr, offset);
		size_t common_size = min(a_end, chunk_end) - common_start;

		ret.emplace_back(a.offset + off_alloc, buf_ptr, common_size);
		ptr = a_end;
		buf_ptr += common_size;
	}

	return ret;
}


void FSClient::obtain_inode(unsigned long ino, cb_dsio_t cb, request_t* req)
{
	/* Check if the inode is in the cache and the cache entry not stale */
	bool found = false;

	{
		shared_lock lk(m_inode_cache);
		auto i = inode_cache.find(ino);
		if (i != inode_cache.end())
		{
			auto& [t,c_node] = i->second;

			auto t_now = get_monotonic_time();
			if (t <= t_now && (t_now - t) < 1000000000ULL)
			{
				cnt_inode_cache_hit.fetch_add(1, memory_order_relaxed);

				/* Copy to avoid carrying locks */
				req->inodes.emplace_back(c_node);
				req->c_inode = &req->inodes.back();

				found = true;
			}
		}
	}

	/* Call callback outside of lock */
	if (found)
	{
		req->finished_reqs.fetch_add(2, memory_order_acq_rel);
		cb(req);
		return;
	}

	cnt_inode_cache_miss.fetch_add(1, memory_order_relaxed);

	/* Remove all stale cache entries */
	{
		unique_lock lk(m_inode_cache);

		auto t_now = get_monotonic_time();

		for (auto i = inode_cache.begin(); i != inode_cache.end();)
		{
			auto cur = i++;

			auto t = cur->first;
			if (t > t_now || (t_now - t) >= 1000000000ULL)
				inode_cache.erase(cur);
		}
	}

	/* Read inode */
	req->inodes.emplace_back();
	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_obtain_inode, this, cb), req);
}

void FSClient::cb_obtain_inode(cb_dsio_t cb, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	auto& node = req->inodes.back();

	if (req->io_error || node.type == inode_t::TYPE_FREE)
	{
		req->finished_reqs.fetch_add(1, memory_order_acq_rel);
		cb(req);
		return;
	}

	/* Add inode to cache if not cached in the meantime */
	{
		unique_lock lk(m_inode_cache);

		if (inode_cache.find(node.node_id) == inode_cache.end())
			inode_cache.emplace(node.node_id, make_pair(get_monotonic_time(), node));
	}

	/* Return inode */
	req->c_inode = &node;

	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	cb(req);
}


void FSClient::expunge_cached_inode(unsigned long ino)
{
	unique_lock lk(m_inode_cache);
	inode_cache.erase(ino);
}


void FSClient::cb_getfsattr(request_t* req)
{
	if (req->finished_reqs.fetch_add(1, memory_order_acq_rel) != 3)
		return;

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	req->fs_attr->size = sb.usable_size;
	req->fs_attr->used = req->block_allocator.count_allocated() * 1024 * 1024UL;

	req->fs_attr->inodes = sb.inode_count;
	req->fs_attr->inodes_used = req->inode_allocator.count_allocated();

	finish_request(req, err::SUCCESS);
}

sdfs::async_handle_t FSClient::getfsattr(sdfs::fs_attr_t* dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->fs_attr = dst;

	/* Read block allocator and inode allocator */
	read_block_allocator(req->block_allocator, bind_front(&FSClient::cb_getfsattr, this), req);
	read_inode_allocator(req->inode_allocator, bind_front(&FSClient::cb_getfsattr, this), req);

	return req->handle;
}


void FSClient::cb_lookup(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	if (node.type == inode_t::TYPE_DIRECTORY)
	{
		/* Search for entry */
		unsigned long found_id = 0;
		for (auto& [name, node_id] : node.files)
		{
			if (name == req->name && node_id != 0)
			{
				found_id = node_id;
				break;
			}
		}

		if (found_id > 0)
		{
			/* Retrieve the entry's inode */
			req->inodes.pop_back();
			req->inodes.emplace_back();

			read_inode(found_id, req->inodes.back(),
					bind_front(&FSClient::cb_lookup2, this), req);
			return;
		}
	}
	else if (node.type == inode_t::TYPE_FILE)
	{
		/* Return error */
		finish_request(req, err::NOTDIR);
		return;
	}

	/* Return NOENT */
	finish_request(req, err::NOENT);
}

void FSClient::cb_lookup2(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	if (node.type != inode_t::TYPE_DIRECTORY && node.type != inode_t::TYPE_FILE)
	{
		/* This is actually a dangling link in the parent directory - for
		 * robustness, just ignore it. */
		finish_request(req, err::NOENT);
		return;
	}

	/* Fill out the destination st_buf */
	fill_st_buf(&node, req->st_buf);
	finish_request(req, err::SUCCESS);
}

sdfs::async_handle_t FSClient::lookup(
		unsigned long parent_ino, const char* name, struct stat* dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->name = name;
	req->st_buf = dst;

	/* Read inode */
	req->inodes.emplace_back();
	read_inode(parent_ino, req->inodes.back(),
			bind_front(&FSClient::cb_lookup, this), req);

	return req->handle;
}


void FSClient::cb_getattr(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	if (node.type != inode_t::TYPE_DIRECTORY && node.type != inode_t::TYPE_FILE)
	{
		finish_request(req, err::NOENT);
		return;
	}

	/* Fill out the destination st_buf */
	fill_st_buf(&node, req->st_buf);
	finish_request(req, err::SUCCESS);
}

sdfs::async_handle_t FSClient::getattr(unsigned long ino, struct stat& dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->st_buf = &dst;

	/* Read inode */
	req->inodes.emplace_back();
	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_getattr, this), req);

	return req->handle;
}


void FSClient::cb_readdir(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	switch (node.type)
	{
	case inode_t::TYPE_FILE:
		finish_request(req, err::NOTDIR);
		return;

	case inode_t::TYPE_DIRECTORY:
		break;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	for (const auto& [name, ino] : node.files)
	{
		sdfs::dir_entry_t e{};
		e.ino = ino;
		e.name = name;

		req->dir_entries->push_back(e);
	}

	finish_request(req, err::SUCCESS);
}

sdfs::async_handle_t FSClient::readdir(unsigned long ino, std::vector<sdfs::dir_entry_t>& dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->dir_entries = &dst;

	/* Read directory inode */
	req->inodes.emplace_back();
	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_readdir, this), req);

	return req->handle;
}


void FSClient::cb_mkdir(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	switch (req->inodes.front().type)
	{
	case inode_t::TYPE_DIRECTORY:
		break;

	case inode_t::TYPE_FILE:
		finish_request(req, err::NOTDIR);
		return;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	/* Check for space */
	if (!req->inodes.front().enough_space_for_file(req->name))
	{
		finish_request(req, err::NOSPC);
		return;
	}

	/* Allocate a new inode */
	req->inodes.emplace_back();
	allocate_inode(req->inodes.back().node_id,
			bind_front(&FSClient::cb_mkdir2, this), req);

}

void FSClient::cb_mkdir2(int res, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (res != err::SUCCESS)
	{
		finish_request(req, res);
		return;
	}

	/* Check supplied name here s.t. it happens from a different thread */
	if (req->name.size() == 0)
	{
		finish_request(req, err::INVAL);
		return;
	}
	else if (req->name.size() > 255)
	{
		finish_request(req, err::NAMETOOLONG);
		return;
	}

	/* Populate directory */
	auto& node = req->inodes.back();

	node.type = inode_t::TYPE_DIRECTORY;
	node.nlink = 2;
	node.size = 2;
	node.mtime = get_wt_now();

	node.files.emplace_back(".", node.node_id);
	node.files.emplace_back("..", req->inodes.front().node_id);

	/* Write inode */
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_mkdir3, this), req);
}

void FSClient::cb_mkdir3(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Update parent */
	auto& node = req->inodes.front();

	node.size++;
	node.nlink++;

	node.files.emplace_back(req->name, req->inodes.back().node_id);
	node.mtime = get_wt_now();

	/* Write parent */
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_mkdir4, this), req);
}

void FSClient::cb_mkdir4(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	fill_st_buf(&req->inodes.back(), req->st_buf);
	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::mkdir(unsigned long parent, const char* name, struct stat& dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->name = name;
	req->st_buf = &dst;

	/* Read parent inode and check for space */
	req->inodes.emplace_back();
	read_inode(parent, req->inodes.back(),
			bind_front(&FSClient::cb_mkdir, this), req);

	return req->handle;
}


void FSClient::cb_rmdir(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	switch (req->inodes.front().type)
	{
	case inode_t::TYPE_DIRECTORY:
		break;

	case inode_t::TYPE_FILE:
		finish_request(req, err::NOTDIR);
		return;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	auto& parent = req->inodes.front();

	/* Check that the names are not '.' or '..' */
	if (req->name == "." || req->name == "..")
	{
		finish_request(req, err::INVAL);
		return;
	}

	/* Find file */
	auto i = parent.files.begin();
	for (; i != parent.files.end() && get<0>(*i) != req->name; i++);

	if (i == parent.files.end())
	{
		finish_request(req, err::NOENT);
		return;
	}

	auto ino = get<1>(*i);

	/* Update parent inode */
	parent.nlink--;
	parent.size--;
	parent.files.erase(i);

	/* Load child inode */
	req->inodes.emplace_back();
	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_rmdir2, this), req);
}

void FSClient::cb_rmdir2(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	if (node.type == inode_t::TYPE_DIRECTORY)
	{
		/* Ensure that the directory is empty */
		if (node.files.size() > 2)
		{
			finish_request(req, err::NOTEMPTY);
			return;
		}
	}
	else if (node.type != inode_t::TYPE_FREE)
	{
		finish_request(req, err::NOTDIR);
		return;
	}

	if (req->dst_ino)
		*req->dst_ino = node.node_id;

	/* Write parent inode */
	auto& parent = req->inodes.front();
	write_inode(parent.node_id, parent,
			bind_front(&FSClient::cb_rmdir3, this), req);

	if (req->auto_free_inode)
	{
		/* Write child inode */
		node.type = inode_t::TYPE_FREE;
		write_inode(node.node_id, node,
				bind_front(&FSClient::cb_rmdir3, this), req);

		/* Free inode */
		free_inode(node.node_id, bind_front(&FSClient::cb_rmdir3, this), req);

		/* Expunge inode from the cache */
		expunge_cached_inode(node.node_id);
	}
}

void FSClient::cb_rmdir3(request_t* req)
{
	unsigned nr_reqs = req->auto_free_inode ? 9 : 3;
	if (req->finished_reqs.fetch_add(1, memory_order_acq_rel) != nr_reqs)
		return;

	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::rmdir(unsigned long parent, const char* name,
		bool auto_free_inode, unsigned long* ino,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->name = name;
	req->auto_free_inode = auto_free_inode;
	req->dst_ino = ino;

	/* Read parent inode */
	req->inodes.emplace_back();
	read_inode(parent, req->inodes.back(),
			bind_front(&FSClient::cb_rmdir, this), req);

	return req->handle;
}


void FSClient::cb_create(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	switch (req->inodes.front().type)
	{
	case inode_t::TYPE_DIRECTORY:
		break;

	case inode_t::TYPE_FILE:
		finish_request(req, err::NOTDIR);
		return;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	/* Check for space */
	if (!req->inodes.front().enough_space_for_file(req->name))
	{
		finish_request(req, err::NOSPC);
		return;
	}

	/* Allocate a new inode */
	req->inodes.emplace_back();
	allocate_inode(req->inodes.back().node_id,
			bind_front(&FSClient::cb_create2, this), req);

}

void FSClient::cb_create2(int res, request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (res != err::SUCCESS)
	{
		finish_request(req, res);
		return;
	}

	/* Check supplied name here s.t. it happens from a different thread */
	if (req->name.size() == 0)
	{
		finish_request(req, err::INVAL);
		return;
	}
	else if (req->name.size() > 255)
	{
		finish_request(req, err::NAMETOOLONG);
		return;
	}

	/* Populate inode */
	auto& node = req->inodes.back();

	node.type = inode_t::TYPE_FILE;
	node.nlink = 1;
	node.mtime = get_wt_now();

	/* Write inode */
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_create3, this), req);
}

void FSClient::cb_create3(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Update parent */
	auto& node = req->inodes.front();

	node.size++;
	node.nlink++;

	node.files.emplace_back(req->name, req->inodes.back().node_id);
	node.mtime = get_wt_now();

	/* Write parent */
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_create4, this), req);
}

void FSClient::cb_create4(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	fill_st_buf(&req->inodes.back(), req->st_buf);
	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::create(unsigned long parent, const char* name, struct stat& dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->name = name;
	req->st_buf = &dst;

	/* Read parent inode and check for space */
	req->inodes.emplace_back();
	read_inode(parent, req->inodes.back(),
			bind_front(&FSClient::cb_create, this), req);

	return req->handle;
}


void FSClient::cb_unlink(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	switch (req->inodes.front().type)
	{
	case inode_t::TYPE_DIRECTORY:
		break;

	case inode_t::TYPE_FILE:
		finish_request(req, err::NOTDIR);
		return;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	auto& parent = req->inodes.front();

	/* Find file */
	auto i = parent.files.begin();
	for (; i != parent.files.end() && get<0>(*i) != req->name; i++);

	if (i == parent.files.end())
	{
		finish_request(req, err::NOENT);
		return;
	}

	auto ino = get<1>(*i);

	/* Update parent inode */
	parent.nlink--;
	parent.size--;
	parent.files.erase(i);

	/* Load child inode */
	req->inodes.emplace_back();
	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_unlink2, this), req);
}

void FSClient::cb_unlink2(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	auto& node = req->inodes.back();
	switch (node.type)
	{
	case inode_t::TYPE_FILE:
		break;

	case inode_t::TYPE_DIRECTORY:
		finish_request(req, err::ISDIR);
		return;

	default:
		finish_request(req, err::NOENT);
		return;
	}

	if (req->dst_ino)
		*req->dst_ino = node.node_id;

	/* Write parent inode */
	auto& parent = req->inodes.front();
	write_inode(parent.node_id, parent,
			bind_front(&FSClient::cb_unlink3, this), req);

	if (req->auto_free_inode)
	{
		/* Write child inode */
		node.type = inode_t::TYPE_FREE;
		write_inode(node.node_id, node,
				bind_front(&FSClient::cb_unlink3, this), req);

		/* Free inode */
		free_inode(node.node_id, bind_front(&FSClient::cb_unlink3, this), req);

		/* Expunge inode from the cache */
		expunge_cached_inode(node.node_id);

		/* Free blocks */
		free_blocks_of_file(node, bind_front(&FSClient::cb_unlink3, this), req);
	}
}

void FSClient::cb_unlink3(request_t* req)
{
	unsigned nr_reqs = req->auto_free_inode ? 12 : 3;
	if (req->finished_reqs.fetch_add(1, memory_order_acq_rel) != nr_reqs)
		return;

	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::unlink(unsigned long parent, const char* name,
		bool auto_free_inode, unsigned long* ino,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->name = name;
	req->auto_free_inode = auto_free_inode;
	req->dst_ino = ino;

	/* Read parent inode */
	req->inodes.emplace_back();
	read_inode(parent, req->inodes.back(),
			bind_front(&FSClient::cb_unlink, this), req);

	return req->handle;
}


void FSClient::cb_free_inode_explicit(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	/* Write child inode */
	auto& node = req->inodes.back();

	node.type = inode_t::TYPE_FREE;
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_free_inode_explicit2, this), req);

	/* Free inode */
	free_inode(node.node_id, bind_front(&FSClient::cb_free_inode_explicit2, this), req);

	/* Expunge indoe from the cache */

	/* Free blocks */
	free_blocks_of_file(node, bind_front(&FSClient::cb_free_inode_explicit2, this), req);
}

void FSClient::cb_free_inode_explicit2(request_t* req)
{
	if (req->finished_reqs.fetch_add(1, memory_order_acq_rel) != 10)
		return;

	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::free_inode_explicit(unsigned long ino,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;

	/* Read inode */
	req->inodes.emplace_back();

	read_inode(ino, req->inodes.back(),
			bind_front(&FSClient::cb_free_inode_explicit, this), req);

	return req->handle;
}


void FSClient::cb_read(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error || !req->c_inode)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Check request parameters
	 * If the offset == file size, EOF will be returned later.
	 * (the last clause checks for overflow) */
	if (
			(req->offset > req->c_inode->size) ||
			req->size + req->offset < req->offset)
	{
		finish_request(req, err::INVAL);
		return;
	}

	req->size = min(req->c_inode->size - req->offset, req->size);
	*req->dst_size = req->size;

	if (req->size == 0)
	{
		finish_request(req, err::SUCCESS);
		return;
	}

	/* Map requested chunk to allocations */
	auto chunks = map_chunk(*req->c_inode, req->offset, req->size);
	if (chunks.size() == 0)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Read data */
	req->finished_reqs.store(0, memory_order_release);
	req->expected_reqs = chunks.size() - 1;

	for (auto [o_d, o_b, s] : chunks)
		dsc.read(req->rd_buf + o_b, o_d, s, cb_read2, req);
}

void FSClient::cb_read2(size_t handle, int res, void* arg)
{
	auto req = reinterpret_cast<request_t*>(arg);

	/* NOTE: This assumes that bool-writes do not cause conflicts that turn an
	 * existing or written true-value into false */
	if (res != err::SUCCESS)
		req->io_error = true;

	auto cnt_reqs = req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	if (cnt_reqs != req->expected_reqs)
		return;

	req->fsc->finish_request(req, req->io_error ? err::IO : err:: SUCCESS);
}

sdfs::async_handle_t FSClient::read(
		unsigned long ino, size_t offset, size_t size, size_t& dst_size, char* buf,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->offset = offset;
	req->size = size;
	req->dst_size = &dst_size;
	req->rd_buf = buf;

	/* Obtain inode */
	obtain_inode(ino, bind_front(&FSClient::cb_read, this), req);

	return req->handle;
}


void FSClient::cb_write(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error || !req->c_inode)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Adapt offset for append writes */
	if (req->append)
		req->offset = req->c_inode->size;

	/* Check request parameters
	 * (the last clause checks for overflow) */
	if (
			req->offset > req->c_inode->size ||
			req->size + req->offset < req->offset)
	{
		finish_request(req, err::INVAL);
		return;
	}

	if (req->size == 0)
	{
		finish_request(req, err::SUCCESS);
		return;
	}

	/* Expunge inode from the cache s.t. no partly altered version of it remains
	 * cached. */
	req->inodes.emplace_back(*req->c_inode);
	req->c_inode = nullptr;
	auto& node = req->inodes.back();

	expunge_cached_inode(node.node_id);

	/* Allocate additional space if required */
	auto req_end = req->offset + req->size;
	auto allocated_size = node.get_allocated_size();
	if (allocated_size < req_end)
	{
		allocate_blocks_for_file(node, req_end - allocated_size,
				bind_front(&FSClient::cb_write2, this), req);
	}
	else
	{
		cb_write2(req);
	}
}

void FSClient::cb_write2(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, req->err_no_spc ? err::NOSPC : err::IO);
		return;
	}

	/* Update inode */
	auto& node = req->inodes.back();

	node.size = max(node.size, req->offset + req->size);
	node.mtime = get_wt_now();

	/* Write inode */
	write_inode(node.node_id, node, bind_front(&FSClient::cb_write3, this), req);
}

void FSClient::cb_write3(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	/* Map chunk to allocations */
	auto chunks = map_chunk(req->inodes.back(), req->offset, req->size);
	if (chunks.size() == 0)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Write data */
	req->finished_reqs.store(0, memory_order_release);
	req->expected_reqs = chunks.size() - 1;

	for (auto [o_d, o_b, s] : chunks)
		dsc.write(req->wr_buf + o_b, o_d, s, cb_write4, req);
}

void FSClient::cb_write4(size_t handle, int res, void* arg)
{
	auto req = reinterpret_cast<request_t*>(arg);

	/* NOTE: This assumes that bool-writes do not cause conflicts that turn an
	 * existing or written true-value into false */
	if (res != err::SUCCESS)
		req->io_error = true;

	auto cnt_reqs = req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	if (cnt_reqs != req->expected_reqs)
		return;

	req->fsc->finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::write(
		unsigned long ino, off_t offset, size_t size, const char* buf,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;

	if (offset == -1)
		req->append = true;
	else
		req->offset = offset;

	req->size = size;
	req->wr_buf = buf;

	/* Obtain inode */
	obtain_inode(ino, bind_front(&FSClient::cb_write, this), req);

	return req->handle;
}


void FSClient::cb_truncate(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error || !req->c_inode)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Expunge inode from the cache s.t. no partly altered version of it remains
	 * cached. */
	req->inodes.emplace_back(*req->c_inode);
	req->c_inode = nullptr;
	auto& node = req->inodes.back();

	expunge_cached_inode(node.node_id);

	/* Free blocks */
	free_blocks_of_file(node, bind_front(&FSClient::cb_truncate2, this), req);
}

void FSClient::cb_truncate2(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	if (req->io_error)
	{
		finish_request(req, err::IO);
		return;
	}

	/* Remove allocations from inode and set size to 0 */
	auto& node = req->inodes.back();
	node.allocations.clear();

	node.size = 0;

	/* Write inode */
	write_inode(node.node_id, node,
			bind_front(&FSClient::cb_truncate3, this), req);
}

void FSClient::cb_truncate3(request_t* req)
{
	req->finished_reqs.load(memory_order_acquire);

	finish_request(req, req->io_error ? err::IO : err::SUCCESS);
}

sdfs::async_handle_t FSClient::truncate(
		unsigned long ino,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;

	/* Obtain inode */
	obtain_inode(ino, bind_front(&FSClient::cb_truncate, this), req);

	return req->handle;
}
