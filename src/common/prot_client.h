#ifndef __COMMON_PROT_CLIENT_H
#define __COMMON_PROT_CLIENT_H

#include <memory>
#include "common/prot_common.h"
#include "common/error_codes.h"

static_assert(sizeof(unsigned long) >= 8);

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

	struct getfattr : public msg
	{
		unsigned long node_id;

		getfattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 8;
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
		static constexpr size_t msg_size = 4*8;
	};

	struct getfattr : public msg
	{
		int res{};

		enum type_t : unsigned char
		{
			FT_FILE = 1,
			FT_DIRECTORY
		};

		unsigned char type{};

		size_t nlink{};
		unsigned long mtime{};
		size_t size{};

		getfattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4 + 1 + 3*8;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

};
};

#endif /* __COMMON_PROT_CLIENT_H */
