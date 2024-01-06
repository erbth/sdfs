#include <stdexcept>
#include "config.h"
#include "prot_dd_mgr.h"
#include "serialization.h"

extern "C"  {
#include <endian.h>
}

using namespace std;
using namespace ser;

namespace prot
{
namespace dd_mgr_fe
{

namespace req
{
	query_dds::query_dds()
		: msg((unsigned) msg_nums::QUERY_DDS)
	{
	}

	size_t query_dds::serialize(char* buf) const
	{
		size_t size = 8;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
		}

		return size;
	}

	void query_dds::parse(const char* buf, size_t size)
	{
		if (size != 4)
			throw invalid_msg_size(num, size);
	}


	unique_ptr<msg> parse(const char* buf, size_t size)
	{
		if (size < 4)
			throw invalid_msg_size(0, size);

		int n = sread_u32(buf);
		switch (n)
		{
			case (unsigned) msg_nums::QUERY_DDS:
			{
				auto msg = make_unique<query_dds>();
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
	query_dds::query_dds()
		: msg((unsigned) msg_nums::QUERY_DDS)
	{
	}

	size_t query_dds::serialize(char* buf) const
	{
		auto cnt = dds.size();
		if (cnt > 65535)
			throw invalid_argument("too many dds");

		size_t size = 10 + cnt * 6;

		if (buf)
		{
			swrite_u32(buf, size - 4);
			swrite_u32(buf, num);
			swrite_u16(buf, cnt);

			for (auto& d : dds)
			{
				swrite_u32(buf, d.id);
				swrite_u16(buf, d.port);
			}
		}

		return size;
	}

	void query_dds::parse(const char* buf, size_t size)
	{
		if (size < 6)
			throw invalid_msg_size(num, size);

		unsigned cnt = sread_u16(buf);
		if (size - 6 != cnt * 6)
			throw invalid_msg_size(num, size);

		for (unsigned i = 0; i < cnt; i++)
		{
			dd desc;
			desc.id = sread_u32(buf);
			desc.port = sread_u16(buf);

			if (desc.id == 0)
				throw invalid_msg("dd id 0");

			if (desc.port < SDFS_DD_PORT_START || desc.port > SDFS_DD_PORT_END)
				throw invalid_msg("invalid dd port");

			dds.push_back(desc);
		}
	}


	unique_ptr<msg> parse(const char* buf, size_t size)
	{
		if (size < 4)
			throw invalid_msg_size(0, size);

		int n = sread_u32(buf);
		switch (n)
		{
			case (unsigned) msg_nums::QUERY_DDS:
			{
				auto msg = make_unique<query_dds>();
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
