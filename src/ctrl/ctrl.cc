#include <cstdio>
#include <cstdlib>
#include <exception>
#include "config.h"
#include "common/exceptions.h"
#include "ctrl_ctx.h"

using namespace std;


void main_exc()
{
	ctrl_ctx ctx;
	ctx.initialize();

	fprintf(stderr, "ready.\n");

	ctx.main();
}

int main(int argc, char** argv)
{
	fprintf(stderr, "sdfs-ctrl version %d.%d.%d starting...\n",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH);

	try
	{
		main_exc();
		return EXIT_SUCCESS;
	}
	catch (const invalid_cmd_args& e)
	{
		fprintf(stderr, "Usage: sdfs-ctrl <id> [<bind address>]\n\n%s\n",
				e.what());

		return EXIT_FAILURE;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
