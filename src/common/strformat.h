#ifndef __COMMON_STRFORMAT_H
#define __COMMON_STRFORMAT_H

#include <string>

std::string format_size_si(size_t size);
std::string format_size_bin(size_t size);

std::string format_hexstr(const char* buf, size_t size);

#endif /* __COMMON_STRFORMAT_H */
