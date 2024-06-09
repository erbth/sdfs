#ifndef __COMMON_PROTOCOLS_H
#define __COMMON_PROTOCOLS_H

#include "common/protocols.h"
#include "common/serialization.h"

namespace prot
{

/* Length includes the size field */
inline size_t serialize_hdr(char*& ptr,
		uint32_t length, uint32_t number, uint64_t seq)
{
	if (ptr)
	{
		ser::swrite_u32(ptr, length - 4);
		ser::swrite_u32(ptr, number);
		ser::swrite_u64(ptr, seq);
	}
	return 16;
}


namespace client
{
	enum client_msg_num_t : unsigned {
		REQ_CONNECT = 1,
		RESP_ACCEPT,

		REQ_PROBE,
		RESP_PROBE,

		REQ_GETATTR,
		RESP_GETATTR,

		REQ_READ,
		RESP_READ,

		REQ_WRITE,
		RESP_WRITE
	};
};

};

#endif /* __COMMON_PROTOCOLS_H */
