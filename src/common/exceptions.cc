#include "exceptions.h"

using namespace std;


invalid_cmd_args::invalid_cmd_args(const string& msg)
	: msg(msg)
{
}

const char* invalid_cmd_args::what() const noexcept
{
	return msg.c_str();
}


cmd_args_help::cmd_args_help()
{
}

const char* cmd_args_help::what() const noexcept
{
	return "help option specified on commandline";
}
