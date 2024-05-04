#ifndef __COMMON_PROT_DD_H
#define __COMMON_PROT_DD_H

#include <memory>
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

	struct read : public msg
	{
		uint64_t request_id;

		size_t offset;
		size_t length;

		read();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 3*8;
	};

	struct write : public msg
	{
		uint64_t request_id;

		size_t offset;
		size_t length;

		const char* data;
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

		/* Size usable by ctrl (without dd header) */
		size_t size;

		/* Size of underlying storage device */
		size_t raw_size;

		getattr();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4 + 16 + 8 + 8;
	};

	struct read : public msg
	{
		uint64_t request_id;
		int res{};

		size_t data_length{};
		const char* data = nullptr;

		read();
		read(uint64_t request_id, int res);

		/* The data will NOT be serialized, and the return value will NOT
		 * include the data size. */
		size_t serialize(char* buf) const override;

		/* Size MUST include the data size - so size is simply the received
		 * message payload size, like for the other messages. */
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 8 + 4;
	};

	struct write : public msg
	{
		uint64_t request_id;
		int res{};
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

};
};

#endif /* __COMMON_PROT_DD_H */
