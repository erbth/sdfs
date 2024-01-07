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


#endif /* __COMMON_MSG_UTILS_H */
