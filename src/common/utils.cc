#include <cerrno>
#include <system_error>
#include "utils.h"

extern "C" {
#include <unistd.h>
}

using namespace std;

void simple_read(int fd, char* buf, size_t size)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = read(fd, buf + pos, size - pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "read");

		if (ret == 0)
			throw runtime_error("encountered EOF");

		pos += ret;
	}
}

void simple_write(int fd, const char* buf, size_t size)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = write(fd, buf + pos, size - pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "read");

		if (ret == 0)
			throw runtime_error("write returned zero");

		pos += ret;
	}
}
