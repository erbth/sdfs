#include <cstdio>
#include <cstdlib>
#include <exception>
#include "config.h"
#include "common/daemon_utils.h"
#include "dd_mgr_ctx.h"

using namespace std;


void main_exc()
{
	dd_mgr_ctx ctx;
	ctx.initialize();

	fprintf(stderr, "ready.\n");
	sdfs_systemd_notify_ready();

	ctx.main();
}

int main(int argc, char** argv)
{
	fprintf(stderr, "sdfs-dd-mgr version %d.%d.%d starting...\n",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH);

	try
	{
		main_exc();
		return EXIT_SUCCESS;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
