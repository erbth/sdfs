#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include "config.h"
#include "common/utils.h"
#include "common/strformat.h"
#include "utils.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
}

using namespace std;


void main_exc(const string& dev)
{
	WrappedFD wfd;
	wfd.set_errno(open(dev.c_str(), O_RDWR | O_CLOEXEC), "open");

	auto di = read_and_validate_device_header(wfd.get_fd());

	printf("id:          %u (gid: %s)\n", di.id, format_gid(di.gid).c_str());
	printf("size:        %s (%s)\n",
			format_size_si(di.size).c_str(),
			format_size_bin(di.size).c_str());

	printf("usable size: %s\n", format_size_bin(di.usable_size()).c_str());
}

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: sdfs-ddinfo <device>\n");
		return EXIT_FAILURE;
	}

	try
	{
		main_exc(string(argv[1]));
		return EXIT_SUCCESS;
	}
	catch (exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
