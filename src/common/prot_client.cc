#include <cstring>
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

msg::msg(int num, uint64_t req_id)
	: prot::msg(num), req_id(req_id)
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


	readdir::readdir()
		: msg(READDIR)
	{
	}

	size_t readdir::serialize(char* buf) const
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

	void readdir::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		node_id = sread_u64(buf);
	}


	create::create()
		: msg(CREATE)
	{
	}

	size_t create::serialize(char* buf) const
	{
		if (name.size() > 255)
			throw invalid_argument("name may be at most 255 characters long");

		size_t size = 16 + msg_size_base + name.size();

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_u64(buf, parent_node_id);
			swrite_u8(buf, name.size());

			memcpy(buf, name.c_str(), name.size());
		}

		return size;
	}

	void create::parse(const char* buf, size_t size)
	{
		if (size < 12 + msg_size_base)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		parent_node_id = sread_u64(buf);
		auto namesz = sread_u8(buf);

		if (size != 12 + msg_size_base + namesz)
			throw invalid_msg_size(num, size);

		name = string(buf, namesz);
	}


	read::read()
		: msg(READ)
	{
	}

	size_t read::serialize(char* buf) const
	{
		size_t size = 16 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_u64(buf, node_id);
			swrite_u64(buf, offset);
			swrite_u64(buf, this->size);
		}

		return size;
	}

	void read::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		node_id = sread_u64(buf);
		offset = sread_u64(buf);
		this->size = sread_u64(buf);
	}


	write::write()
		: msg(WRITE)
	{
	}

	size_t write::serialize(char* buf) const
	{
		size_t size = 16 + msg_size_base;

		if (buf)
		{
			swrite_u32(buf, size + this->size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_u64(buf, node_id);
			swrite_u64(buf, offset);
			swrite_u64(buf, this->size);
		}

		return size;
	}

	void write::parse(const char* buf, size_t size)
	{
		if (size < 12 + msg_size_base)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		node_id = sread_u64(buf);
		offset = sread_u64(buf);
		this->size = sread_u64(buf);

		if (this->size + msg_size_base + 12 != size)
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

			case GETFATTR:
			{
				auto msg = make_unique<getfattr>();
				msg->parse(buf, size);
				return msg;
			}

			case READDIR:
			{
				auto msg = make_unique<readdir>();
				msg->parse(buf, size);
				return msg;
			}

			case CREATE:
			{
				auto msg = make_unique<create>();
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
			swrite_u64(buf, this->size);
			swrite_u64(buf, allocated_size);
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
		this->size = sread_u64(buf);
		allocated_size = sread_u64(buf);
	}


	readdir::readdir()
		: msg(READDIR)
	{
	}

	size_t readdir::serialize(char* buf) const
	{
		size_t size = 16 + msg_size_base;

		for (const auto& e : entries)
		{
			if (e.name.size() > 255)
				throw invalid_argument("file name must be at most 255 chars long");

			size += entry_base_size + e.name.size();
		}

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_i32(buf, res);
			swrite_u64(buf, entries.size());

			for (const auto& e : entries)
			{
				swrite_u64(buf, e.node_id);
				swrite_u8(buf, e.type);
				swrite_u8(buf, e.name.size());

				memcpy(buf, e.name.c_str(), e.name.size());
				buf += e.name.size();
			}
		}

		return size;
	}

	void readdir::parse(const char* buf, size_t size)
	{
		auto ptr = buf;

		if (size < 12 + msg_size_base)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(ptr);
		res = sread_i32(ptr);
		size_t cnt_entries = sread_u64(ptr);

		auto max_ptr = buf + (size - 4);
		for (size_t i = 0; i < cnt_entries; i++)
		{
			if (ptr + entry_base_size > max_ptr)
				throw invalid_msg_size(num, size);

			entry e;
			e.node_id = sread_u64(ptr);
			if (e.node_id == 0)
				throw runtime_error("received directory entry with inode id 0");

			e.type = sread_u8(ptr);

			auto namesz = sread_u8(ptr);
			if (ptr + namesz > max_ptr)
				throw invalid_msg_size(num, size);

			e.name = string(ptr, namesz);
			ptr += namesz;

			entries.push_back(move(e));
		}

		if (ptr != max_ptr)
			throw invalid_msg_size(num, size);
	}


	create::create()
		: msg(CREATE)
	{
	}

	create::create(uint64_t req_id, int res)
		: msg(CREATE, req_id), res(res)
	{
	}

	size_t create::serialize(char* buf) const
	{
		size_t size = 16 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_i32(buf, res);
			swrite_u64(buf, node_id);
			swrite_u64(buf, nlink);
			swrite_u64(buf, mtime);
			swrite_u64(buf, this->size);
		}

		return size;
	}

	void create::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		res = sread_i32(buf);
		node_id = sread_u64(buf);
		nlink = sread_u64(buf);
		mtime = sread_u64(buf);
		this->size = sread_u64(buf);
	}


	read::read()
		: msg(READ)
	{
	}

	read::read(uint64_t req_id, int res)
		: msg(READ, req_id), res(res)
	{
	}

	size_t read::serialize(char* buf) const
	{
		size_t size = 16 + msg_size_base;

		if (buf)
		{
			swrite_u32(buf, size + this->size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_i32(buf, res);
			swrite_u64(buf, this->size);
		}

		return size;
	}

	void read::parse(const char* buf, size_t size)
	{
		if (size < 12 + msg_size_base)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		res = sread_i32(buf);
		this->size = sread_u64(buf);

		if (size != 12 + msg_size_base + this->size)
			throw invalid_msg_size(num, size);

		data = this->size > 0 ? buf : nullptr;
	}


	write::write()
		: msg(WRITE)
	{
	}

	write::write(uint64_t req_id, int res)
		: msg(WRITE, req_id), res(res)
	{
	}

	size_t write::serialize(char* buf) const
	{
		size_t size = 16 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u64(buf, req_id);

			swrite_i32(buf, res);
		}

		return size;
	}

	void write::parse(const char* buf, size_t size)
	{
		if (size != 12 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

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

			case GETFATTR:
			{
				auto msg = make_unique<getfattr>();
				msg->parse(buf, size);
				return msg;
			}

			case READDIR:
			{
				auto msg = make_unique<readdir>();
				msg->parse(buf, size);
				return msg;
			}

			case CREATE:
			{
				auto msg = make_unique<create>();
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
