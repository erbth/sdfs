#include "exceptions.h"

extern "C" {
#include <netdb.h>
}

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


gai_exception::gai_exception(int code, const string& msg)
	: msg(msg + string(gai_strerror(code)))
{
}

const char* gai_exception::what() const noexcept
{
	return msg.c_str();
}


io_timeout_exception::io_timeout_exception()
{
}

const char* io_timeout_exception::what() const noexcept
{
	return "io timeout";
}


io_eof_exception::io_eof_exception()
{
}

const char* io_eof_exception::what() const noexcept
{
	return "encountered EOF";
}
