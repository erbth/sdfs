#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include "config.h"
#include "common/exceptions.h"
#include "ctrl_ctx.h"

using namespace std;


void main_exc(int argc, char** argv)
{
	if (argc > 2)
		throw invalid_cmd_args("invalid arguments");

	bool format = false;
	if (argc == 2)
	{
		if (strcmp(argv[1], "--format") == 0)
			format = true;
		else
			throw invalid_cmd_args("invalid arguments");
	}

	if (format)
	{
		printf("The filesystem will be formatted; all data will be lost.\n"
				"Continue? [y|N] ");

		fflush(stdout);

		char* lineptr = nullptr;
		size_t n = 0;
		auto ret = getline(&lineptr, &n, stdin);
		if (ret < 0)
		{
			if (lineptr)
				free(lineptr);

			throw runtime_error("Failed to read user input.");
		}

		if (ret != 2 || (strncmp(lineptr, "y\n", 2) != 0 && strncmp(lineptr, "Y\n", 2) != 0))
			format = false;

		free(lineptr);
	}

	ctrl_ctx ctx;
	ctx.initialize(format);

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
		main_exc(argc, argv);
		return EXIT_SUCCESS;
	}
	catch (const invalid_cmd_args& e)
	{
		fprintf(stderr, "Usage: sdfs-ctrl [--format]\n\n%s\n",
				e.what());

		return EXIT_FAILURE;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "ERROR: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
