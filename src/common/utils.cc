#include <cerrno>
#include <system_error>
#include <filesystem>
#include "config.h"
#include "utils.h"

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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
