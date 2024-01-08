#ifndef __COMMON_MSG_UTILS_H
#define __COMMON_MSG_UTILS_H

#include <cerrno>
#include <stdexcept>
#include <system_error>
#include <memory>
#include "common/utils.h"
#include "common/fixed_buffer.h"
#include "common/dynamic_buffer.h"
#include "common/prot_common.h"
#include "common/exceptions.h"
#include "common/serialization.h"

extern "C" {
#include <unistd.h>
#include <poll.h>
}


/* Send- / receive helpers */
/* For dgram and seqpacket sockets; timeout is in milliseconds, 0 returns
 * immediately and -1 waits indefinitely */
template <std::unique_ptr<prot::msg>(&P)(const char*, size_t)>
std::unique_ptr<prot::msg> receive_packet_msg(int fd, int timeout,
		size_t max_size = 65536)
{
	if (timeout != 0)
	{
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN
		};

		auto ret = check_syscall(poll(&pfd, 1, timeout), "poll");
		if (ret == 0 || !(pfd.revents & EPOLLIN))
			return nullptr;
	}

	fixed_buffer buf(max_size);
	auto cnt_read = read(fd, buf.ptr(), max_size);
	if (cnt_read < 0)
		throw std::system_error(errno, std::generic_category(), "read");

	if (cnt_read == 0)
		return nullptr;

	return P(buf.ptr(), cnt_read);
}

void send_packet_msg(int fd, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	ssize_t len = msg.serialize(buf.ptr());
	auto ret = check_syscall(write(fd, buf.ptr(), len), "write");
	if (ret != len)
		throw std::runtime_error("write packet returned differing byte count");
}


template <std::unique_ptr<prot::msg>(&P)(const char*, size_t)>
std::unique_ptr<prot::msg> receive_stream_msg(int fd, int timeout)
{
	dynamic_buffer buf;

	if (timeout < 1)
		throw std::invalid_argument("timeout must be > 0");

	struct timespec t1, t2;
	check_syscall(clock_gettime(CLOCK_MONOTONIC, &t1), "clock_gettime");

	/* First read size */
	size_t size = 4;
	buf.ensure_size(2048);

	size_t pos = 0;
	while (pos < size)
	{
		/* Check timeout */
		if (timeout <= 0)
			throw io_timeout_exception();

		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN
		};

		auto ret = check_syscall(poll(&pfd, 1, timeout), "poll");
		if (ret > 0)
		{
			auto cnt_read = check_syscall(
					read(fd, buf.ptr() + pos, size == 4 ? 1 : (size - pos)),
					"read");

			if (cnt_read == 0)
				throw io_eof_exception();

			pos += cnt_read;

			/* Length received */
			if (pos == 4)
				size += ser::read_u32(buf.ptr());
		}

		/* Adjust timeout */
		check_syscall(clock_gettime(CLOCK_MONOTONIC, &t2), "clock_gettime");
		auto delay = (t2.tv_sec - t1.tv_sec) * 1000 +
			((t2.tv_nsec - t1.tv_nsec) + 500000) / 1000000;

		timeout -= delay;
	}

	return P(buf.ptr() + 4, size - 4);
}

template <std::unique_ptr<prot::msg>(&P)(const char*, size_t), unsigned num>
inline std::unique_ptr<prot::msg> receive_stream_msg(int fd, int timeout)
{
	auto msg = receive_stream_msg<P>(fd, timeout);
	if (msg->num != num)
		throw std::runtime_error("protocol violation");

	return msg;
}

void send_stream_msg(int fd, const prot::msg& msg)
{
	dynamic_buffer buf;
	buf.ensure_size(msg.serialize(nullptr));
	ssize_t len = msg.serialize(buf.ptr());
	simple_write(fd, buf.ptr(), len);
}


#endif /* __COMMON_MSG_UTILS_H */
