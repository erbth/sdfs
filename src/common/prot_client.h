#ifndef __COMMON_PROT_CLIENT_H
#define __COMMON_PROT_CLIENT_H

#include <memory>
#include "common/prot_common.h"

namespace prot
{
namespace client
{

struct msg : public prot::msg
{
	uint64_t req_id;

	msg(int num);
};

namespace req
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		GETFATTR,
		LISTDIR,
		READ,
		WRITE
	};

	struct getattr : public msg
	{
		getattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

namespace reply
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		GETFATTR,
		LISTDIR,
		READ,
		WRITE
	};

	struct getattr : public msg
	{
		size_t size_total;
		size_t size_used;

		size_t inodes_total;
		size_t inodes_used;

		getattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 8 + 4*8;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

};
};

#endif /* __COMMON_PROT_CLIENT_H */
