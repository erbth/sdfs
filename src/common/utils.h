#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include <cerrno>
#include <limits>
#include <stdexcept>
#include <system_error>

extern "C" {
#include <unistd.h>
}

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
			close(fd);
	}

	inline WrappedFD(WrappedFD&& o)
		: fd(o.fd)
	{
		o.fd = -1;
	}

	inline WrappedFD& operator=(WrappedFD&& o)
	{
		if (fd >= 0)
			close(fd);

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
			close(fd);

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
};


inline int check_syscall(int ret, const char* msg)
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

#endif /* __COMMON_UTILS_H */
