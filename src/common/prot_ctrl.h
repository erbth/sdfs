#ifndef __COMMON_PROT_CTRL_H
#define __COMMON_PROT_CTRL_H

#include <memory>
#include "common/prot_common.h"

static_assert(sizeof(unsigned) >= 4);

namespace prot
{
namespace ctrl
{

namespace req
{
	/* The last message id must be smaller than 0x7fffffff */
	enum msg_nums : unsigned {
		CTRLINFO = 1,
		FETCH_INODE
	};

	struct ctrlinfo : public msg
	{
		unsigned id;

		ctrlinfo();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4;
	};

	struct fetch_inode : public msg
	{
		uint64_t req_id;
		unsigned long node_id;

		fetch_inode();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 16;
	};
};

namespace reply
{
	enum msg_nums : unsigned {
		FETCH_INODE = 0x80000000
	};

	struct fetch_inode : public msg
	{
		uint64_t req_id;
		const char* inode = nullptr;

		fetch_inode();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 8;
		static constexpr size_t msg_size_inode = 4096;
	};
};

std::unique_ptr<msg> parse(const char* buf, size_t size);

};
};

#endif /* __COMMON_PROT_CTRL_H */
