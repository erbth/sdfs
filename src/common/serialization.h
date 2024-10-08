#ifndef __COMMON_SERIALIZATION_H
#define __COMMON_SERIALIZATION_H

#include <cstdint>

extern "C" {
#include <endian.h>
}


namespace ser
{

inline void swrite_u8(char*& ptr, uint8_t v)
{
	*((uint8_t*) ptr) = v;
	ptr += sizeof(v);
}

inline void swrite_u16(char*& ptr, uint16_t v)
{
	v = htole16(v);
	*((uint16_t*) ptr) = v;
	ptr += sizeof(v);
}

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


inline void swrite_i32(char*& ptr, int32_t v)
{
	swrite_u32(ptr, (uint32_t) v);
}


inline uint8_t sread_u8(const char*& ptr)
{
	uint8_t v = *((const uint8_t*) ptr);
	ptr += sizeof(v);
	return v;
}

inline uint16_t sread_u16(const char*& ptr)
{
	uint16_t v = le16toh(*((const uint16_t*) ptr));
	ptr += sizeof(v);
	return v;
}

inline uint32_t sread_u32(const char*& ptr)
{
	uint32_t v = le32toh(*((const uint32_t*) ptr));
	ptr += sizeof(v);
	return v;
}

inline uint64_t sread_u64(const char*& ptr)
{
	uint64_t v = le64toh(*((const uint64_t*) ptr));
	ptr += sizeof(v);
	return v;
}


inline int32_t sread_i32(const char*& ptr)
{
	return (int32_t) sread_u32(ptr);
}


inline uint8_t read_u8(const char* ptr)
{
	return *((const uint16_t*) ptr);
}

inline uint16_t read_u16(const char* ptr)
{
	return le16toh(*((const uint16_t*) ptr));
}

inline uint32_t read_u32(const char* ptr)
{
	return le32toh(*((const uint32_t*) ptr));
}

inline uint64_t read_u64(const char* ptr)
{
	return le64toh(*((const uint64_t*) ptr));
}

};


#endif /* __COMMON_SERIALIZATION_H */
