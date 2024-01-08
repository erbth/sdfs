#ifndef __COMMON_PROT_DD_H
#define __COMMON_PROT_DD_H

#include <memory>
#include "common/fixed_buffer.h"
#include "common/prot_common.h"

namespace prot
{
namespace dd
{

namespace req
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		READ,
		WRITE
	};

	struct getattr : public msg
	{
		getattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);
	};

	struct read
	{
		uint64_t request_id;

		size_t offset;
		size_t length;
	};

	struct write
	{
		uint64_t request_id;

		size_t offset;
		size_t length;

		const char* buf;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

namespace reply
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		READ,
		WRITE
	};

	struct getattr : public msg
	{
		unsigned id;
		char gid[16];

		size_t size;
		size_t usable_size;

		getattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4 + 16 + 8 + 8;
	};

	struct read
	{
		uint64_t request_id;
		unsigned result;

		const char* buf;
	};

	struct write
	{
		uint64_t request_id;
		unsigned result;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

};
};

#endif /* __COMMON_PROT_DD_H */
