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


	read::read()
		: msg(READ)
	{
	}

	size_t read::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, request_id);
			swrite_u64(buf, offset);
			swrite_u64(buf, length);
		}

		return size;
	}

	void read::parse(const char* buf, size_t size)
	{
		if (size != 4 + msg_size)
			throw invalid_msg_size(num, size);

		request_id = sread_u64(buf);
		offset = sread_u64(buf);
		length = sread_u64(buf);
	}


	write::write()
		: msg(WRITE)
	{
	}

	size_t write::serialize(char* buf) const
	{
		if (buf)
		{
			swrite_u32(buf, header_size + length - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, request_id);
			swrite_u64(buf, offset);
			swrite_u64(buf, length);
		}

		return header_size;
	}

	void write::parse(const char* buf, size_t size)
	{
		if (size < header_size - 4)
			throw invalid_msg_size(num, size);

		request_id = sread_u64(buf);
		offset = sread_u64(buf);
		length = sread_u64(buf);

		if (size != header_size - 4 + length)
			throw invalid_msg_size(num, size);

		data = buf;
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

			case READ:
			{
				auto msg = make_unique<read>();
				msg->parse(buf, size);
				return msg;
			}

			case WRITE:
			{
				auto msg = make_unique<write>();
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


	read::read()
		: msg(READ)
	{
	}

	read::read(uint64_t request_id, int res)
		: msg(READ), request_id(request_id), res(res)
	{
	}

	size_t read::serialize(char* buf) const
	{
		size_t size = 8 + msg_size_base;

		if (buf)
		{
			swrite_u32(buf, size + data_length - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, request_id);
			swrite_i32(buf, res);
		}

		return size;
	}

	void read::parse(const char* buf, size_t size)
	{
		if (size < msg_size_base + 4)
			throw invalid_msg_size(num, size);

		request_id = sread_u64(buf);
		res = sread_i32(buf);

		data = buf;
		data_length = size - (msg_size_base + 4);
	}


	write::write()
		: msg(WRITE)
	{
	}

	write::write(uint64_t request_id, int res)
		: msg(WRITE), request_id(request_id), res(res)
	{
	}

	size_t write::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, request_id);
			swrite_i32(buf, res);
		}

		return size;
	}

	void write::parse(const char* buf, size_t size)
	{
		if (size != 4 + msg_size)
			throw invalid_msg_size(num, size);

		request_id = sread_u64(buf);
		res = sread_i32(buf);
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

			case READ:
			{
				auto msg = make_unique<read>();
				msg->parse(buf, size);
				return msg;
			}

			case WRITE:
			{
				auto msg = make_unique<write>();
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
