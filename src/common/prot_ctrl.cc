#include <cstring>
#include "common/serialization.h"
#include "prot_ctrl.h"

using namespace std;
using namespace ser;

namespace prot
{
namespace ctrl
{

namespace req
{
	ctrlinfo::ctrlinfo()
		: msg(CTRLINFO)
	{
	}

	size_t ctrlinfo::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u32(buf, id);
		}

		return size;
	}

	void ctrlinfo::parse(const char* buf, size_t size)
	{
		if (size != msg_size + 4)
			throw invalid_msg_size(num, size);

		id = sread_u32(buf);
	}


	fetch_inode::fetch_inode()
		: msg(FETCH_INODE)
	{
	}

	size_t fetch_inode::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);
			swrite_u64(buf, node_id);
		}

		return size;
	}

	void fetch_inode::parse(const char* buf, size_t size)
	{
		if (size != msg_size + 4)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);
		node_id = sread_u64(buf);
	}


	lock_inode_directory::lock_inode_directory()
		: msg(LOCK_INODE_DIRECTORY)
	{
	}

	size_t lock_inode_directory::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);
		}

		return size;
	}

	void lock_inode_directory::parse(const char* buf, size_t size)
	{
		if (size != 4 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);
	}
};

namespace reply
{
	fetch_inode::fetch_inode()
		: msg(FETCH_INODE)
	{
	}

	size_t fetch_inode::serialize(char* buf) const
	{
		size_t size = 8 + msg_size_base;
		if (inode)
			size += msg_size_inode;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);

			if (inode)
			{
				memcpy(buf, inode, msg_size_inode);
				buf += msg_size_inode;
			}
		}

		return size;
	}

	void fetch_inode::parse(const char* buf, size_t size)
	{
		bool have_inode = false;

		if (size == 4 + msg_size_base + msg_size_inode)
			have_inode = true;
		else if (size != 4 + msg_size_base)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);

		if (have_inode)
			inode = buf;
		else
			inode = nullptr;
	}


	lock_inode_directory::lock_inode_directory()
		: msg(LOCK_INODE_DIRECTORY)
	{
	}

	size_t lock_inode_directory::serialize(char* buf) const
	{
		size_t size = 8 + msg_size;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);

			swrite_u64(buf, req_id);
		}

		return size;
	}

	void lock_inode_directory::parse(const char* buf, size_t size)
	{
		if (size != 4 + msg_size)
			throw invalid_msg_size(num, size);

		req_id = sread_u64(buf);
	}
};


unique_ptr<msg> parse(const char* buf, size_t size)
{
	if (size < 4)
		throw invalid_msg_size(0, size);

	auto n = sread_u32(buf);
	switch (n)
	{
		case req::CTRLINFO:
		{
			auto msg = make_unique<req::ctrlinfo>();
			msg->parse(buf, size);
			return msg;
		}

		case req::FETCH_INODE:
		{
			auto msg = make_unique<req::fetch_inode>();
			msg->parse(buf, size);
			return msg;
		}

		case reply::FETCH_INODE:
		{
			auto msg = make_unique<reply::fetch_inode>();
			msg->parse(buf, size);
			return msg;
		}

		case req::LOCK_INODE_DIRECTORY:
		{
			auto msg = make_unique<req::lock_inode_directory>();
			msg->parse(buf, size);
			return msg;
		}

		case reply::LOCK_INODE_DIRECTORY:
		{
			auto msg = make_unique<reply::lock_inode_directory>();
			msg->parse(buf, size);
			return msg;
		}

		default:
			throw invalid_msg_num(n);
	}
}

};
};
