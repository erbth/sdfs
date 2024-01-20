#include "prot_common.h"

using namespace std;

namespace prot
{

msg::msg(int num)
	: num(num)
{
}

msg::~msg()
{
}


exception::exception(const string& msg)
	: msg(msg)
{
}

const char* exception::what() const noexcept
{
	return msg.c_str();
}


invalid_msg_num::invalid_msg_num(unsigned num)
	:
		exception("Invalid message number: " + to_string(num)),
		num(num)
{
}

invalid_msg_size::invalid_msg_size(unsigned num, size_t size)
	:
		exception("Invalid message size: " + to_string(size) +
				" (msg number: " + to_string(num) + ")"),
		num(num), size(size)
{
}

invalid_msg::invalid_msg(const string& msg)
	: exception(msg)
{
}

};
