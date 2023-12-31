#ifndef __COMMON_SERIALIZATION_H
#define __COMMON_SERIALIZATION_H

#include <cstdint>

extern "C" {
#include <endian.h>
}


namespace ser
{

inline void swrite_u32(char*& ptr, uint32_t v)
{
	v = htole32(v);
	*((uint32_t*) ptr) = v;
	ptr += sizeof(v);
}

inline void swrite_u64(char*& ptr, uint64_t v)
{
	v = htole64(v);
	*((uint64_t*) ptr) = v;
	ptr += sizeof(v);
}


inline uint32_t sread_u32(char*& ptr)
{
	uint32_t v = htole32(*((uint32_t*) ptr));
	ptr += sizeof(v);
	return v;
}

inline uint64_t sread_u64(char*& ptr)
{
	uint64_t v = htole64(*((uint64_t*) ptr));
	ptr += sizeof(v);
	return v;
}

};


#endif /* __COMMON_SERIALIZATION_H */
