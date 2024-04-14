#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include <cerrno>
#include <limits>
#include <mutex>
#include <string>
#include <stdexcept>
#include <system_error>

extern "C" {
#include <unistd.h>
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

	inline WrappedFD& operator=(WrappedFD&& o)
	{
		if (fd >= 0)
			::close(fd);

		fd = o.fd;
		o.fd = -1;

		return *this;
	}

	/* If value is < 0, throw system_error */
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

#endif /* __COMMON_UTILS_H */
