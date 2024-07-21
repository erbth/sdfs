#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include <cerrno>
#include <limits>
#include <mutex>
#include <condition_variable>
#include <string>
#include <stdexcept>
#include <system_error>
#include <atomic>
#include "common/dynamic_buffer.h"

extern "C" {
#include <unistd.h>
#include <netinet/in.h>
}

/* Primitive types */
typedef uint64_t req_id_t;


class WrappedFD final
{
protected:
	int fd;

public:
	inline WrappedFD()
		: fd(-1)
	{
	}

	inline WrappedFD(int fd)
		: fd(fd)
	{
	}

	inline ~WrappedFD()
	{
		if (fd >= 0)
			::close(fd);
	}

	inline WrappedFD(WrappedFD&& o)
		: fd(o.fd)
	{
		o.fd = -1;
	}

	inline WrappedFD& operator=(WrappedFD&& o) noexcept
	{
		if (fd >= 0)
			::close(fd);

		fd = o.fd;
		o.fd = -1;

		return *this;
	}

	inline int operator=(int nfd) noexcept
	{
		if (fd >= 0)
			::close(fd);

		fd = nfd;

		return fd;
	}

	/* If value is < 0, throw system_error
	 * It is guaranteed that this will not throw if new_fd >= 0. */
	inline void set_errno(int new_fd, const char* msg)
	{
		if (new_fd < 0)
			throw std::system_error(errno, std::generic_category(), msg);

		if (fd >= 0)
			::close(fd);

		fd = new_fd;
	}

	inline int get_fd()
	{
		return fd;
	}

	inline operator bool() const
	{
		return fd >= 0;
	}

	inline void close()
	{
		if (fd >= 0)
		{
			::close(fd);
			fd = -1;
		}
	}
};


template <typename T>
inline T check_syscall(T ret, const char* msg)
{
	if (ret < 0)
		throw std::system_error(errno, std::generic_category(), msg);

	return ret;
}


template <typename T>
T next_power_of_two(T i)
{
	if (i == 0)
		return 0;

	T v = 1;
	while (v < i)
	{
		if (v > std::numeric_limits<T>::max() / 2)
			throw std::overflow_error("would overflow");

		v *= 2;
	}

	return v;
}

/* Throws runtime_error if not enough data could be read/written; the
 * read-functions throw io_eof_exceptions; timeout is in milliseconds and must
 * be > 0; if the timeout elapses, the function throws an io_timeout_exception.
 * */
void simple_read(int fd, char* buf, size_t size);
void simple_read_timeout(int fd, char* buf, size_t size, unsigned timeout);
void simple_write(int fd, const char* buf, size_t size);

void ensure_sdfs_run_dir();
void ensure_sdfs_run_dir(const std::string& subdir);

void parse_gid(char* gid, const std::string& s);


/* Get current wallclock time in microseconds */
unsigned long get_wt_now();

/* Get current monotonic time in nanoseconds */
unsigned long long get_monotonic_time();


/* Temporary unlock a unique_lock, regaining the lock when the unlocked-instance
 * goes out of scope (is destroyed) */
template <class T>
class unlocked final
{
protected:
	std::unique_lock<T>& lk;

public:
	unlocked(std::unique_lock<T>& lk)
		: lk(lk)
	{
		lk.unlock();
	}

	~unlocked()
	{
		lk.lock();
	}
};


class buffer_pool_returner final
{
protected:
	dynamic_aligned_buffer_pool& pool;

public:
	dynamic_aligned_buffer buf;

	inline buffer_pool_returner(dynamic_aligned_buffer_pool& pool, dynamic_aligned_buffer&& buf)
		: pool(pool), buf(std::move(buf))
	{
	}

	inline buffer_pool_returner(buffer_pool_returner&& o)
		: pool(o.pool), buf(std::move(o.buf))
	{
	}

	inline ~buffer_pool_returner()
	{
		if (buf)
			pool.return_buffer(std::move(buf));
	}
};


std::string in_addr_str(const struct sockaddr_in6& addr);
std::string errno_str(int code);
std::string gai_error_str(int code);


class sync_point final
{
protected:
	std::mutex m;
	std::condition_variable cv;

	bool flagged = false;

public:
	inline void flag()
	{
		{
			std::unique_lock lk(m);
			flagged = true;
		}
		cv.notify_one();
	}

	inline void wait()
	{
		std::unique_lock lk(m);
		while (!flagged)
			cv.wait(lk);
	}

	/* Reset after waiting */
	inline void wait_reset()
	{
		std::unique_lock lk(m);
		while (!flagged)
			cv.wait(lk);

		flagged = false;
	}
};

/* A predefined callback function for use with sync_point */
void cb_sync_point(void* arg);


/* A special synchronization point to make asynchronous sdfs IOs synchronous */
class io_promise final
{
protected:
	std::mutex m;
	std::condition_variable cv;

	bool _finished = false;
	size_t _handle{};
	int _result{};

public:
	inline void finish(size_t handle, int res)
	{
		{
			std::unique_lock lk(m);
			_finished = true;
			_handle = handle;
			_result = res;
		}
		cv.notify_one();
	}

	inline int wait()
	{
		std::unique_lock lk(m);
		while (!_finished)
			cv.wait(lk);

		_finished = false;

		return _result;
	}

	inline size_t handle()
	{
		std::unique_lock lk(m);
		return _handle;
	}
};

void cb_io_promise(size_t handle, int res, void* arg);


/* A cealing function for alignment - round up to the next multiple of @param
 * alignment. @param alignment MUST BE a power of two. */
template<typename T>
inline T align_up(T alignment, T value)
{
	return (value + alignment - 1) & ~(alignment - 1);
}


/* For simple reference counting lifetime management */
/* Ensure minimum data size */
static_assert(sizeof(unsigned long) == 8);

class reference_count_t final
{
protected:
	std::atomic<unsigned long> _count;

public:
	reference_count_t(unsigned long initial)
	{
		_count.store(initial, std::memory_order_release);
	}

	reference_count_t& operator=(reference_count_t&& o) = delete;

	inline unsigned long inc()
	{
		return _count.fetch_add(1, std::memory_order_acq_rel) + 1;
	}

	inline unsigned long dec()
	{
		return _count.fetch_sub(1, std::memory_order_acq_rel) - 1;
	}

	inline operator bool()
	{
		return _count.load(std::memory_order_acquire) > 0;
	}

	inline unsigned long value()
	{
		return _count.load(std::memory_order_acquire);
	}


	/* "Smart" reference management
	 * The reference-type itself is NOT mt safe - additional precautions have to
	 * be taken if required. However this should only rarely be needed in
	 * practice. */
	class reference final
	{
	protected:
		reference_count_t* _refc;

	public:
		inline reference()
			: _refc(nullptr)
		{ }

		inline reference(reference_count_t& refc)
			: _refc(&refc)
		{
			_refc->inc();
		}

		inline reference(reference_count_t* refc)
			: _refc(refc)
		{
			_refc->inc();
		}

		inline ~reference()
		{
			if (_refc)
				_refc->dec();
		}


		inline reference(reference&& o)
			: _refc(o._refc)
		{
			o._refc = nullptr;
		}

		inline reference* operator=(reference&& o)
		{
			_refc = o._refc;
			o._refc = nullptr;
			return this;
		}
	};
};


#endif /* __COMMON_UTILS_H */
