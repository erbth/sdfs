#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include "config.h"
#include "common/exceptions.h"
#include "common/daemon_utils.h"
#include "ctrl_ctx.h"

using namespace std;


void main_exc(int argc, char** argv)
{
	ctrl_ctx ctx;
	ctx.initialize();

	fprintf(stderr, "ready.\n");
	sdfs_systemd_notify_ready();

	ctx.main();
}

int main(int argc, char** argv)
{
	fprintf(stderr, "sdfs-ctrl version %d.%d.%d starting...\n",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH);

	try
	{
		main_exc(argc, argv);
		return EXIT_SUCCESS;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
