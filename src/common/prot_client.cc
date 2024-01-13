#include "prot_client.h"
#include "serialization.h"

using namespace std;
using namespace ser;


namespace prot
{
namespace client
{

msg::msg(int num)
	: prot::msg(num)
{
}

namespace req
{
	getattr::getattr()
		: msg(GETATTR)
	{
	}

	size_t getattr::serialize(char* buf) const
	{
		size_t size = 8 + 8;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);
		}

		return size;
	}

	void getattr::parse(const char* buf, size_t size)
	{
		if (size != 4 + 8)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);
	}


	unique_ptr<msg> parse(const char* buf, size_t size)
	{
		if (size < 4)
			throw invalid_msg_size(0, size);

		auto n = sread_u32(buf);
		switch (n)
		{
			case GETATTR:
			{
				auto msg = make_unique<getattr>();
				msg->parse(buf, size);
				return msg;
			}

			default:
				throw invalid_msg_num(n);
		};
	}
};

namespace reply
{
	getattr::getattr()
		: msg(GETATTR)
	{
	}

	size_t getattr::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);

			swrite_u64(buf, size_total);
			swrite_u64(buf, size_used);
			swrite_u64(buf, inodes_total);
			swrite_u64(buf, inodes_used);
		}

		return size;
	}

	void getattr::parse(const char* buf, size_t size)
	{
		if (size != msg_size + 4)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		size_total = sread_u64(buf);
		size_used = sread_u64(buf);
		inodes_total = sread_u64(buf);
		inodes_used = sread_u64(buf);
	}


	unique_ptr<msg> parse(const char* buf, size_t size)
	{
		if (size < 4)
			throw invalid_msg_size(0, size);

		auto n = sread_u32(buf);
		switch (n)
		{
			case GETATTR:
			{
				auto msg = make_unique<getattr>();
				msg->parse(buf, size);
				return msg;
			}

			default:
				throw invalid_msg_num(n);
		};
	}
};

};
};
