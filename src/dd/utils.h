#ifndef __UTILS_H
#define __UTILS_H

#include <string>

extern "C" {
#include <unistd.h>
}

/* If the given fd does not refer to a regular file or block device, this
 * function throws a runtime_error */
size_t get_device_size(int fd);

/* Throws runtime_error if not enough data could be read/written */
void simple_read(int fd, char* buf, size_t size);

void simple_pread(int fd, char* buf, size_t size, off_t offset);
void simple_pwrite(int fd, char* buf, size_t size, off_t offset);


void generate_dd_gid(char* buf);


class DeviceInfo
{
public:
	unsigned id{};
	char gid[16]{};
	size_t size{};

	size_t usable_size();

	/* Writes exactly 4096 bytes */
	void serialize_header(char* buffer);

	/* Expects 4096 bytes */
	void parse_header(char* buffer);
};

/* Ensures that the size is correct */
DeviceInfo read_and_validate_device_header(int fd);

std::string format_gid(const char* gid);

#endif /* __UTILS_H */
