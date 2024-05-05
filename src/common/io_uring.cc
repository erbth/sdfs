/** See also liburing */
#include <atomic>
#include <cstring>
#include "common/open_list.h"
#include "common/io_uring.h"

extern "C" {
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/time_types.h>
#include "kernel_hdr/io_uring.h"
}

using namespace std;

static_assert(sizeof(unsigned) == 4);


struct app_sq_ring
{
	unsigned* head;
	unsigned* tail;
	unsigned* ring_mask;
	unsigned* ring_entries;
	unsigned* flags;
	unsigned* array;
};

struct app_cq_ring
{
	unsigned* head;
	unsigned* tail;
	unsigned* ring_mask;
	unsigned* ring_entries;
	struct io_uring_cqe* cqes;
};

template <typename T>
inline T load_acquire(const T* p)
{
	return atomic_load_explicit(reinterpret_cast<const atomic<T>*>(p),
			memory_order_acquire);
}

template <typename T>
inline void store_release(T* p, T v)
{
	atomic_store_explicit(reinterpret_cast<atomic<T>*>(p), v,
			memory_order_release);
}


struct IOUringCtx final
{
	unsigned entries;

	struct io_uring_params p;
	WrappedFD ufd;

	/* mmap'd regions */
	char* ptr_sq_ring = nullptr;
	struct io_uring_sqe* ptr_sqes = nullptr;
	char* ptr_cq_ring = nullptr;

	size_t map_sq_ring_length = 0;
	size_t map_sqes_length = 0;
	size_t map_cq_ring_length = 0;

	app_sq_ring sq_ring{};
	app_cq_ring cq_ring{};

	unsigned sq_ring_mask = 0;
	unsigned cq_ring_mask = 0;

	/* Request processing */
	unsigned req_in_flight = 0;

	/* Request list */
	open_list<IOUring::complete_cb_t> req_list;

	void setup_io_uring()
	{
		memset(&p, 0, sizeof(p));

		ufd.set_errno(
				syscall(__NR_io_uring_setup, entries, &p),
				"io_uring_setup");
	}

	void map_rings()
	{
		/* mmap sq ring */
		map_sq_ring_length = p.sq_off.array + p.sq_entries * sizeof(__u32);
		ptr_sq_ring = (char*) mmap(nullptr, map_sq_ring_length,
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ufd.get_fd(),
				IORING_OFF_SQ_RING);

		if (ptr_sq_ring == MAP_FAILED)
			throw system_error(errno, generic_category(), "mmap sq ring failed");

		sq_ring.head = (unsigned*) (ptr_sq_ring + p.sq_off.head);
		sq_ring.tail = (unsigned*) (ptr_sq_ring + p.sq_off.tail);
		sq_ring.ring_mask = (unsigned*) (ptr_sq_ring + p.sq_off.ring_mask);
		sq_ring.ring_entries = (unsigned*) (ptr_sq_ring + p.sq_off.ring_entries);
		sq_ring.flags = (unsigned*) (ptr_sq_ring + p.sq_off.flags);
		sq_ring.array = (unsigned*) (ptr_sq_ring + p.sq_off.array);

		sq_ring_mask = *sq_ring.ring_mask;

		/* mmap sqe buffer */
		map_sqes_length = p.sq_entries * sizeof(struct io_uring_sqe);
		ptr_sqes = (struct io_uring_sqe*) mmap(nullptr, map_sqes_length,
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ufd.get_fd(),
				IORING_OFF_SQES);

		if (ptr_sqes == MAP_FAILED)
			throw system_error(errno, generic_category(), "mmap sqe buffer failed");

		/* mmap cq ring */
		map_cq_ring_length = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
		ptr_cq_ring = (char*) mmap(nullptr, map_cq_ring_length,
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ufd.get_fd(),
				IORING_OFF_CQ_RING);

		cq_ring.head = (unsigned*) (ptr_cq_ring + p.cq_off.head);
		cq_ring.tail = (unsigned*) (ptr_cq_ring + p.cq_off.tail);
		cq_ring.ring_mask = (unsigned*) (ptr_cq_ring + p.cq_off.ring_mask);
		cq_ring.ring_entries = (unsigned*) (ptr_cq_ring + p.cq_off.ring_entries);
		cq_ring.cqes = (struct io_uring_cqe*) (ptr_cq_ring + p.cq_off.cqes);

		cq_ring_mask = *cq_ring.ring_mask;
	}

	void initialize_rings()
	{
		auto sq_head = load_acquire(sq_ring.head);
		auto sq_tail = *sq_ring.tail;

		auto cq_tail = load_acquire(cq_ring.tail);
		auto cq_head = *cq_ring.head;

		if (*sq_ring.ring_entries != entries)
		{
			throw runtime_error("Allocated sq ring entry count does not "
					"match requested entries");
		}

		if (*cq_ring.ring_entries < entries)
			throw runtime_error("Too few cq ring entries");

		/* Check other parameters */
		if (sq_head != sq_tail || cq_head != cq_tail ||
				*sq_ring.ring_mask != *sq_ring.ring_entries - 1 ||
				*cq_ring.ring_mask != *cq_ring.ring_entries - 1)
		{
			throw runtime_error("Invalid io ring configuration");
		}

		/* Identity map sqe array */
		for (unsigned i = 0; i < *sq_ring.ring_entries; i++)
			sq_ring.array[i] = i;
	}

	IOUringCtx(unsigned entries)
		: entries(entries)
	{
		try
		{
			setup_io_uring();
			map_rings();
			initialize_rings();
		}
		catch (...)
		{
			cleanup();
			throw;
		}
	}

	void cleanup()
	{
		/* Clear requests lists */
		while (auto r = req_list.get_head())
		{
			req_list.remove(r);
			delete r;
		}

		/* Unmap shared memory ranges */
		if (ptr_cq_ring)
			munmap(ptr_cq_ring, map_cq_ring_length);

		if (ptr_sqes)
			munmap(ptr_sqes, map_sqes_length);

		if (ptr_sq_ring)
			munmap(ptr_sq_ring, map_sq_ring_length);
	}

	~IOUringCtx()
	{
		cleanup();
	}


	struct io_uring_sqe* next_sqe()
	{
		if (req_in_flight > entries)
			throw runtime_error("too many requests in flight");

		auto head = load_acquire(sq_ring.head);
		auto tail = *sq_ring.tail;

		if (tail - head >= *sq_ring.ring_entries)
			throw runtime_error("sq ring full");

		return &ptr_sqes[tail & sq_ring_mask];
	}

	void submit()
	{
		req_in_flight++;

		auto tail = *sq_ring.tail;
		tail++;
		store_release(sq_ring.tail, tail);

		check_syscall(
				syscall(__NR_io_uring_enter, ufd.get_fd(), 1, 0, 0, nullptr, 0),
				"io_uring_enter");
	}
};


IOUring::IOUring(unsigned entries)
	: ctx(make_unique<IOUringCtx>(next_power_of_two(entries)))
{
}

IOUring::~IOUring()
{
}

void IOUring::submit_poll(int fd, short events, complete_cb_t cb)
{
	auto sqe = ctx->next_sqe();
	memset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_POLL_ADD;
	sqe->fd = fd;
	sqe->poll_events = events;

	auto n = new open_list<complete_cb_t>::node();
	n->elem = cb;

	sqe->user_data = (uintptr_t) n;

	try
	{
		ctx->submit();
	}
	catch (...)
	{
		delete n;
		throw;
	}

	ctx->req_list.add(n);
}

void IOUring::submit_writev(int fd, const struct iovec *iov, int iovcnt,
		off_t offset, int flags, complete_cb_t cb)
{
	auto sqe = ctx->next_sqe();
	memset(sqe, 0, sizeof(*sqe));

	sqe->opcode = IORING_OP_WRITEV;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (decltype(sqe->addr)) iov;
	sqe->len = iovcnt;
	sqe->rw_flags = flags;

	auto n = new open_list<complete_cb_t>::node();
	n->elem = cb;

	sqe->user_data = (uintptr_t) n;

	try
	{
		ctx->submit();
	}
	catch (...)
	{
		delete n;
		throw;
	}

	ctx->req_list.add(n);
}

void IOUring::process_requests(bool block)
{
	auto tail = load_acquire(ctx->cq_ring.tail);
	auto head = *ctx->cq_ring.head;
	unsigned cnt_pending = tail - head;

	if (cnt_pending == 0)
	{
		if (!block)
			return;

		check_syscall(
				syscall(__NR_io_uring_enter, ctx->ufd.get_fd(), 0, 1,
					IORING_ENTER_GETEVENTS, nullptr, 0),
				"io_uring_enter(getevents)");

		tail = load_acquire(ctx->cq_ring.tail);
		cnt_pending = tail - head;
	}

	for (unsigned i = 0; i < cnt_pending; i++)
	{
		auto cqe = &ctx->cq_ring.cqes[(head + i) & ctx->cq_ring_mask];

		auto n = (open_list<complete_cb_t>::node*) (uintptr_t) cqe->user_data;
		auto cb = n->elem;
		ctx->req_list.remove(n);
		delete n;

		cb(cqe->res);
	}

	store_release(ctx->cq_ring.head, head + cnt_pending);
	ctx->req_in_flight -= cnt_pending;
}
