#include <cstring>
#include <cerrno>
#include <system_error>
#include "config.h"
#include "common/utils.h"
#include "common/serialization.h"
#include "common/strformat.h"
#include "common/fixed_buffer.h"
#include "utils.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
}

using namespace std;

size_t get_device_size(int fd)
{
	struct stat s;
	if (fstat(fd, &s) < 0)
		throw system_error(errno, generic_category(), "fstat");

	auto type = s.st_mode & S_IFMT;
	if (type == S_IFBLK)
	{
		size_t dev_size;
		if (ioctl(fd, BLKGETSIZE64, &dev_size) < 0)
			throw system_error(errno, generic_category(), "ioctl");

		return dev_size;
	}
	else if (type == S_IFREG)
	{
		return s.st_size;
	}
	else
	{
		throw runtime_error("Unsupported file type");
	}
}


void simple_read(int fd, char* buf, size_t size)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = read(fd, buf + pos, size - pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "pread");

		if (ret == 0)
			throw runtime_error("encountered EOF");

		pos += ret;
	}
}

void simple_pread(int fd, char* buf, size_t size, off_t offset)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = pread(fd, buf + pos, size - pos, offset + pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "pread");

		if (ret == 0)
			throw runtime_error("encountered EOF");

		pos += ret;
	}
}

void simple_pwrite(int fd, char* buf, size_t size, off_t offset)
{
	size_t pos = 0;
	while (pos < size)
	{
		auto ret = pwrite(fd, buf + pos, size - pos, offset + pos);
		if (ret < 0)
			throw system_error(errno, generic_category(), "pwrite");

		if (ret == 0)
			throw runtime_error("pwrite returned 0");

		pos += ret;
	}
}


void generate_dd_gid(char* buf)
{
	WrappedFD ufd;
	ufd.set_errno(open("/dev/urandom", O_RDONLY), "open(\"/dev/urandom\")");

	simple_read(ufd.get_fd(), buf, 16);
}


size_t DeviceInfo::usable_size()
{
	/* dd header + configuration + directory */
	return size - (4096 + (1 + 100) * 1024 * 1024);
}

void DeviceInfo::serialize_header(char* buffer)
{
	memset(buffer, 0, 4096);
	auto ptr = buffer;

	memcpy(ptr, SDFS_DD_MAGIC, sizeof(SDFS_DD_MAGIC));
	ptr += sizeof(SDFS_DD_MAGIC);

	ser::swrite_u32(ptr, id);

	memcpy(ptr, gid, 16);
	ptr += 16;

	ser::swrite_u64(ptr, size);
}

void DeviceInfo::parse_header(char* buffer)
{
	auto ptr = buffer;
	if (memcmp(ptr, SDFS_DD_MAGIC, sizeof(SDFS_DD_MAGIC)) != 0)
		throw runtime_error("This device/file does not appear to be a dd");

	ptr += sizeof(SDFS_DD_MAGIC);

	id = ser::sread_u32(ptr);

	memcpy(gid, ptr, 16);
	ptr += 16;

	size = ser::sread_u64(ptr);
}

DeviceInfo read_and_validate_device_header(int fd)
{
	auto dev_size = get_device_size(fd);
	if (dev_size < 4096 + (1 + 100) * 1024 * 1024)
		throw runtime_error("This device/file is too small");

	fixed_aligned_buffer buf(4096, 4096);
	simple_pread(fd, buf.ptr(), 4096, dev_size - 4096);

	DeviceInfo di;
	di.parse_header(buf.ptr());

	/* Verify size */
	if (di.size != dev_size)
		throw runtime_error("Device size and size in header differ");

	return di;
}

string format_gid(const char* gid)
{
	return format_hexstr(gid, 16);
}
