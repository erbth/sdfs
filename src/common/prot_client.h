#ifndef __COMMON_PROT_CLIENT_H
#define __COMMON_PROT_CLIENT_H

#include <string>
#include <memory>
#include <vector>
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
	msg(int num, uint64_t req_id);
};

namespace req
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		GETFATTR,
		READDIR,
		CREATE,
		UNLINK,
		MKDIR,
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

	struct readdir : public msg
	{
		unsigned long node_id;

		readdir();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 8;
	};

	struct create : public msg
	{
		unsigned long parent_node_id;
		std::string name;

		create();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 9;
	};


	struct read : public msg
	{
		unsigned long node_id;
		size_t offset;
		size_t size;

		read();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 3*8;
	};

	struct write : public msg
	{
		unsigned long node_id;
		size_t offset;
		size_t size;

		/* Will only be used by parse */
		const char* data = nullptr;

		write();

		/* The data will NOT be serialized, and the return value will NOT
		 * include the data size. */
		size_t serialize(char* buf) const override;

		/* Size MUST include the data size - so size is simply the received
		 * message payload size, like for the other messages. */
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 8*3;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

namespace reply
{
	enum msg_nums : unsigned {
		GETATTR = 1,
		GETFATTR,
		READDIR,
		CREATE,
		UNLINK,
		MKDIR,
		READ,
		WRITE
	};

	enum file_type_t : unsigned char
	{
		FT_FILE = 1,
		FT_DIRECTORY
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

	struct readdir : public msg
	{
		int res{};

		struct entry
		{
			unsigned long node_id{};
			unsigned char type{};
			std::string name;
		};

		std::vector<entry> entries;

		readdir();
		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 4 + 8;
		static constexpr size_t entry_base_size = 10;
	};

	struct create : public msg
	{
		int res{};

		unsigned long node_id{};

		size_t nlink{};
		unsigned long mtime{};
		size_t size{};

		create();
		create(uint64_t req_id, int res);

		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4 + 4*8;
	};

	struct read : public msg
	{
		int res{};

		size_t size = 0;

		/* Will only be used by parse */
		const char* data = nullptr;

		read();
		read(uint64_t req_id, int res);

		/* The data will NOT be serialized, and the return value will NOT
		 * include the data size. */
		size_t serialize(char* buf) const override;

		/* Size MUST include the data size - so size is simply the received
		 * message payload size, like for the other messages. */
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size_base = 4 + 8;
	};

	struct write : public msg
	{
		int res{};

		write();
		write(uint64_t req_id, int res);

		size_t serialize(char* buf) const override;
		void parse(const char* buf, size_t size);

	protected:
		static constexpr size_t msg_size = 4;
	};

	std::unique_ptr<msg> parse(const char* buf, size_t size);
};

};
};

#endif /* __COMMON_PROT_CLIENT_H */
