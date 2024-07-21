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
	const std::string msg;

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

class gai_exception : public std::exception
{
protected:
	const std::string msg;

public:
	gai_exception(int code, const std::string& msg);
	const char* what() const noexcept override;
};

class io_timeout_exception : public std::exception
{
public:
	io_timeout_exception();
	const char* what() const noexcept override;
};

class io_eof_exception : public std::exception
{
public:
	io_eof_exception();
	const char* what() const noexcept override;
};

class invalid_superblock : public std::exception
{
protected:
	const std::string msg;

public:
	invalid_superblock(const std::string& msg);
	const char* what() const noexcept override;
};

#endif /* __COMMON_EXCEPTIONS_H */
