#include <cstdio>
#include <cstdlib>
#include <string>
#include <exception>
#include "config.h"
#include "common/utils.h"
#include "common/strformat.h"
#include "common/daemon_utils.h"
#include "utils.h"
#include "dd_ctx.h"

using namespace std;


void main_exc(const string& dev)
{
	dd_ctx ctx(dev);

	ctx.initialize();

	fprintf(stderr, "ready.\n");
	sdfs_systemd_notify_ready();

	ctx.main();
}

int main(int argc, char** argv)
{
	fprintf(stderr, "sdfs-dd version %d.%d.%d starting...\n",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH);

	if (argc != 2)
	{
		fprintf(stderr, "Usage: sdfs-dd <device>\n");
		return EXIT_FAILURE;
	}

	try
	{
		main_exc(argv[1]);
		return EXIT_SUCCESS;
	}
	catch (exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
