#include <cstdio>
#include <cstdlib>
#include <exception>
#include "common/exceptions.h"
#include "config.h"
#include "fuse_ctx.h"

using namespace std;


void print_help()
{
	fprintf(stderr, R"help(This is sdfs-fuse version %d.%d.%d
FUSE library version: %s

)help",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH,
			fuse_pkgversion());

	printf(R"help(Usage: sdfs-fuse [<options>] <mount point>

The following options are supported:
)help");

	fuse_cmdline_help();
	fuse_lowlevel_help();
}

int main(int argc, char** argv)
{
	try
	{
		sdfs_fuse_ctx ctx(argc, argv);
		ctx.initialize();
		ctx.main();

		return EXIT_SUCCESS;
	}
	catch (const invalid_cmd_args& e)
	{
		fprintf(stderr, "Invalid commandline arguments:\n%s\n\nTry --help\n",
				e.what());

		return EXIT_FAILURE;
	}
	catch (const cmd_args_help&)
	{
		print_help();
		return EXIT_FAILURE;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
