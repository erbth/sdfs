#ifndef __COMMON_EXCEPTIONS_H
#define __COMMON_EXCEPTIONS_H

#include <cerrno>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <string>

class invalid_cmd_args : public std::exception
{
protected:
	std::string msg;

public:
	invalid_cmd_args(const std::string& msg);
	const char* what() const noexcept override;
};

class cmd_args_help : public std::exception
{
public:
	cmd_args_help();
	const char* what() const noexcept override;
};

#endif /* __COMMON_EXCEPTIONS_H */
