#ifndef __COMMON_PROT_DD_MGR_H
#define __COMMON_PROT_DD_MGR_H

#include <vector>
#include <memory>
#include "common/prot_common.h"

namespace prot
{

/* MGR frontend (TCP, usually used by controllers) */
/* 4 byte message id */
namespace dd_mgr_fe
{
	namespace req
	{
		enum struct msg_nums : unsigned {
			QUERY_DDS = 1
		};

		struct query_dds : public msg
		{
			query_dds();

			size_t serialize(char* buf) const override;
			void parse(const char* buf, size_t size);
		};

		std::unique_ptr<msg> parse(const char* buf, size_t size);
	};

	namespace reply
	{
		enum struct msg_nums : unsigned {
			QUERY_DDS = 1
		};

		struct query_dds : public msg
		{
			query_dds();

			struct dd
			{
				unsigned id;
				int port;
			};

			std::vector<dd> dds;

			size_t serialize(char* buf) const override;
			void parse(const char* buf, size_t size);
		};

		std::unique_ptr<msg> parse(const char* buf, size_t size);
	};
};

/* MGR backend (unix domain socket, used by dds) */
namespace dd_mgr_be
{
	namespace req
	{
		enum struct msg_nums : unsigned {
			REGISTER_DD = 1
		};

		struct register_dd : public msg
		{
			register_dd();

			unsigned id;
			int port;

			size_t serialize(char* buf) const override;
			void parse(const char* buf, size_t size);
		};

		std::unique_ptr<msg> parse(const char* buf, size_t size);
	};

	namespace reply
	{
		enum struct msg_nums : unsigned {
			REGISTER_DD = 1
		};

		struct register_dd : public msg
		{
			register_dd();

			size_t serialize(char* buf) const override;
			void parse(const char* buf, size_t size);
		};

		std::unique_ptr<msg> parse(const char* buf, size_t size);
	};
};

};

#endif /* __COMMON_PROT_DD_MGR_H */
