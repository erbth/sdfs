#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <regex>
#include "config.h"
#include "common/exceptions.h"
#include "common/utils.h"
#include "common/fixed_buffer.h"
#include "utils.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
}

using namespace std;


class Args
{
protected:
	int argc;
	char** argv;

	const char* require_arg(const string& arg, int i)
	{
		if ((i + 1) >= argc)
			throw invalid_cmd_args("`" + arg + "' required an argument");

		return argv[i+1];
	}

	unsigned arg_unsigned(const string& arg, int& i)
	{
		auto arg2 = require_arg(arg, i);
		i++;

		if (!regex_match(arg2, regex("^[0-9]+$")))
		{
			throw invalid_cmd_args("`" + arg +
					"' requires an unsigned integer argument");
		}

		return strtoul(arg2, nullptr, 10);
	}

public:
	bool help = false;
	unsigned id;
	string device;

	void parse(int argc, char** argv)
	{
		this->argc = argc;
		this->argv = argv;

		bool have_id = false;
		bool have_device = false;

		for (int i = 1; i < argc; i++)
		{
			auto arg = argv[i];

			if (strlen(arg) > 0 && arg[0] != '-')
			{
				if (have_device)
					throw invalid_cmd_args("Only one device can be specified");

				device = arg;
				have_device = true;
			}
			else if (strcmp(arg, "-i") == 0)
			{
				if (have_id)
					throw invalid_cmd_args("`-i' might be specified only once");

				id = arg_unsigned("-i", i);
				if (id < 1)
					throw invalid_cmd_args("A dd id must be >= 1");

				have_id = true;
			}
			else if (strcmp(arg, "--help") == 0)
			{
				throw cmd_args_help();
			}
			else
			{
				throw invalid_cmd_args("Invalid argument `" + string(arg) + "'");
			}
		}

		/* Ensure all required arguments are given */
		if (!have_device)
			throw invalid_cmd_args("A device is required");

		if (!have_id)
			throw invalid_cmd_args("An id is required");
	}

	static void print_help()
	{
		fprintf(stderr, R"ARGS(sdfs-mkdd version %d.%d.%d
This tool formats a disk for use as sdfs-dd.

Usage: sdfs-mkdd [options] -i <id> <path to device>

Options:
    -i          The new dd's unique numeric id

    --help      Show this help text
)ARGS",
				(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
				(int) SDFS_VERSION_PATCH);
	}
};


void main_exc(const Args& args)
{
	/* Open device file */
	WrappedFD wfd;
	wfd.set_errno(open(args.device.c_str(), O_CLOEXEC | O_RDWR), "open");

	/* dd header + configuration + directory */
	constexpr size_t total_header_size = 4096 + (1 + 100) * 1024 * 1024;

	/* Check device size (and type) */
	auto dev_size = get_device_size(wfd.get_fd());
	if (dev_size < total_header_size)
		throw runtime_error("This device/file is too small");

	/* Check if device is not a scts-dd already */
	char buf[4096];
	simple_pread(wfd.get_fd(), buf, 512, dev_size - 4096);

	if (memcmp(buf, SDFS_DD_MAGIC, sizeof(SDFS_DD_MAGIC)) == 0)
		throw runtime_error("This device/file is already a dd");

	/* Write header */
	printf("Creating sdfs-dd with id %u\n", args.id);

	DeviceInfo di;
	di.id = args.id;
	di.size = dev_size;
	generate_dd_gid(di.gid);

	di.serialize_header(buf);
	simple_pwrite(wfd.get_fd(), buf, 4096, dev_size - 4096);

	/* Zero configuration section + directory */
	memset(buf, 0, 4096);
	for (int i = 0; i < ((1 + 100) * 1024 * 1024) / 4096; i++)
		simple_pwrite(wfd.get_fd(), buf, 4096, dev_size - total_header_size + i * 4096);

	/* fsync */
	check_syscall(fsync(wfd.get_fd()), "fsync");
}

int main(int argc, char** argv)
{
	try
	{
		Args args;
		args.parse(argc, argv);

		main_exc(args);
		return EXIT_SUCCESS;
	}
	catch (cmd_args_help&)
	{
		Args::print_help();
		return EXIT_FAILURE;
	}
	catch (invalid_cmd_args& e)
	{
		fprintf(stderr, "%s\n\nTry --help\n",
				e.what());
		return EXIT_FAILURE;
	}
	catch (exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
