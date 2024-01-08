#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <optional>
#include <regex>
#include "config.h"
#include "common/exceptions.h"
#include "ctrl_ctx.h"

using namespace std;


unsigned parse_id(const char* c)
{
	if (!regex_match(c, regex("^[0-9]+$")))
		throw invalid_cmd_args("id must be an unsigned integer >= 1");

	unsigned id = strtoul(c, nullptr, 10);
	if (id < 1)
		throw invalid_cmd_args("id must be an unsigned integer >= 1");

	return id;
}


void main_exc(unsigned id, const optional<const string>& bind_addr)
{
	ctrl_ctx ctx(id, bind_addr);
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
		if (argc < 2 || argc > 3)
			throw invalid_cmd_args("Invalid number of arguments");

		unsigned id = parse_id(argv[1]);
		optional<string> bind_addr;

		if (argc > 2)
			bind_addr = argv[2];

		main_exc(id, bind_addr);
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
