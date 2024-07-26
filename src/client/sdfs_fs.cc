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
	req->finished_reqs.fetch_add(1, memory_order_acq_rel);
	cb(req);
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
				cb_read_inode_allocator, p);
	}
	catch (...)
	{
		delete p;
		throw;
	}
}

void FSClient::cb_read_inode_allocator(size_t handle, int res, void* arg)
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


void FSClient::cb_getfsattr(request_t* req)
{
	if (req->finished_reqs.load(memory_order_acquire) != 2)
		return;

	if (req->io_error)
		finish_request(req, err::IO);

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
		finish_request(req, err::IO);

	/* Search for entry */

	/* Return entry */
}

sdfs::async_handle_t FSClient::lookup(
		unsigned long parent_ino, const char* name, struct stat* dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	auto req = add_request();

	req->cb_finished = cb_finished;
	req->cb_finished_arg = arg;
	req->st_buf = dst;

	/* Read inode */
	req->inodes.emplace_back();
	//read_inode(req->inodes.back(), bind_front(&FSClient::cb_lookup, this), req);

	return req->handle;
}
