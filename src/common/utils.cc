#include <cerrno>
#include <ctime>
#include <system_error>
#include <filesystem>
#include "config.h"
#include "utils.h"
#include "exceptions.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
}

using namespace std;
namespace fs = std::filesystem;

void simple_read(int fd, char* buf, size_t size)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = read(fd, buf + pos, size - pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "read");

		if (ret == 0)
			throw io_eof_exception();

		pos += ret;
	}
}

void simple_read_timeout(int fd, char* buf, size_t size, unsigned timeout)
{
	if (timeout < 1)
		throw invalid_argument("timeout must be > 0");

	struct timespec t1, t2;
	check_syscall(clock_gettime(CLOCK_MONOTONIC, &t1), "clock_gettime");

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
					read(fd, buf + pos, size - pos),
					"read");

			if (cnt_read == 0)
				throw io_eof_exception();

			pos += cnt_read;
		}

		/* Adjust timeout */
		check_syscall(clock_gettime(CLOCK_MONOTONIC, &t2), "clock_gettime");
		auto delay = (t2.tv_sec - t1.tv_sec) * 1000 +
			((t2.tv_nsec - t1.tv_nsec) + 500000) / 1000000;

		timeout -= delay;
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


void ensure_sdfs_run_dir()
{
	bool exists = true;

	struct stat s;
	auto ret = lstat(SDFS_RUN_DIR, &s);
	if (ret < 0)
	{
		if (errno == ENOENT)
			exists = false;
		else
			check_syscall(ret, "stat(rundir)");
	}

	if (exists)
	{
		if (!(S_ISDIR(s.st_mode)))
			throw runtime_error("The /run-dir exists but is not a directory");
	}
	else
	{
		check_syscall(mkdir(SDFS_RUN_DIR, 0755), "mkdir(rundir)");
	}
}

void ensure_sdfs_run_dir(const string& subdir)
{
	/* Create run dir if required */
	ensure_sdfs_run_dir();

	/* Create subdir */
	bool exists = true;

	auto p = fs::path(SDFS_RUN_DIR) / subdir;

	struct stat s;
	auto ret = lstat(p.c_str(), &s);
	if (ret < 0)
	{
		if (errno == ENOENT)
			exists = false;
		else
			check_syscall(ret, "stat(rundir)");
	}

	if (exists)
	{
		if (!(S_ISDIR(s.st_mode)))
		{
			throw runtime_error(
					"A subdir of the /run-dir exists but is not a directory");
		}
	}
	else
	{
		check_syscall(mkdir(p.c_str(), 0755), "mkdir(rundir)");
	}
}


void parse_gid(char* gid, const string& s)
{
	if (s.size() != 32)
	{
		throw invalid_argument(
				"A hex-represented gid must consist of 32 characters");
	}

	for (int i = 0; i < 16; i++)
	{
		int c1 = s[i*2];
		int c2 = s[i*2 + 1];

		if (c1 >= '0' && c1 <= '9')
		{
			c1 -= '0';
		}
		else if (c1 >= 'A' && c1 <= 'F')
		{
			c1 -= 'A' - 10;
		}
		else if (c1 >= 'a' && c1 <= 'f')
		{
			c1 -= 'a' - 10;
		}
		else
		{
			throw invalid_argument("A hex-represented gid must only consist "
					"of the characters 0-9, A-F, or a-f");
		}

		if (c2 >= '0' && c2 <= '9')
		{
			c2 -= '0';
		}
		else if (c2 >= 'A' && c2 <= 'F')
		{
			c2 -= 'A' - 10;
		}
		else if (c2 >= 'a' && c2 <= 'f')
		{
			c2 -= 'a' - 10;
		}
		else
		{
			throw invalid_argument("A hex-represented gid must only consist "
					"of the characters 0-9, A-F, or a-f");
		}

		gid[i] = c1 * 16 + c2;
	}
}
