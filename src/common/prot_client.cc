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


	getfattr::getfattr()
		: msg(GETFATTR)
	{
	}

	size_t getfattr::serialize(char* buf) const
	{
		size_t size = 16 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_u64(buf, node_id);
		}

		return size;
	}

	void getfattr::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		node_id = sread_u64(buf);
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

			case GETFATTR:
			{
				auto msg = make_unique<getfattr>();
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
		size_t size = 16 + msg_size;

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
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		size_total = sread_u64(buf);
		size_used = sread_u64(buf);
		inodes_total = sread_u64(buf);
		inodes_used = sread_u64(buf);
	}


	getfattr::getfattr()
		: msg(GETFATTR)
	{
	}

	size_t getfattr::serialize(char* buf) const
	{
		size_t size = 16 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_i32(buf, res);
			swrite_u8(buf, type);
			swrite_u64(buf, nlink);
			swrite_u64(buf, mtime);
			swrite_u64(buf, size);
		}

		return size;
	}

	void getfattr::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		res = sread_i32(buf);
		type = sread_u8(buf);
		nlink = sread_u64(buf);
		mtime = sread_u64(buf);
		size = sread_u64(buf);
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

			case GETFATTR:
			{
				auto msg = make_unique<getfattr>();
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
