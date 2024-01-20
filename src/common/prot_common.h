#ifndef __COMMON_PROT_COMMON_H
#define __COMMON_PROT_COMMON_H

#include <exception>
#include <string>

namespace prot
{

struct msg
{
	const unsigned num;

	msg(int num);
	virtual ~msg() = 0;

	virtual size_t serialize(char* buf) const = 0;
};


class exception : public std::exception
{
protected:
	const std::string msg;

public:
	exception(const std::string& msg);
	const char* what() const noexcept override;
};

class invalid_msg_num : public exception
{
public:
	const unsigned num;

	invalid_msg_num(unsigned num);
};

class invalid_msg_size : public exception
{
public:
	const unsigned num;
	const size_t size;

	invalid_msg_size(unsigned num, size_t size);
};

class invalid_msg : public exception
{
public:
	invalid_msg(const std::string& msg);
};

};

#endif /* __COMMON_PROT_COMMON_H */
