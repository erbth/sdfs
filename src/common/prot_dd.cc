#include <cstring>
#include "prot_dd.h"
#include "serialization.h"

using namespace std;
using namespace ser;

namespace prot
{
namespace dd
{

namespace req
{
	getattr::getattr()
		: msg(GETATTR)
	{
	}

	size_t getattr::serialize(char* buf) const
	{
		size_t size = 8;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
		}

		return size;
	}

	void getattr::parse(const char* buf, size_t size)
	{
		if (size != 4)
			throw invalid_msg_size(num, size);
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

			swrite_u32(buf, id);
			memcpy(buf, gid, sizeof(gid));
			buf += sizeof(gid);

			swrite_u64(buf, this->size);
			swrite_u64(buf, raw_size);
		}

		return size;
	}

	void getattr::parse(const char* buf, size_t size)
	{
		if (size != msg_size + 4)
			throw invalid_msg_size(num, size);

		id = sread_u32(buf);
		memcpy(gid, buf, sizeof(gid));
		buf += sizeof(gid);

		this->size = sread_u64(buf);
		raw_size = sread_u64(buf);
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
