#ifndef __COMMON_FILE_CONFIG_H
#define __COMMON_FILE_CONFIG_H

#include <string>
#include <vector>
#include <exception>

struct FileConfig
{
	struct Controller
	{
		std::vector<std::string> addr_strs;
	};

	struct DD
	{
		unsigned id;
		std::string gid;
	};

	struct DDHost
	{
		std::string addr_str;
	};

	std::optional<Controller> controller;
	std::vector<DD> dds;
	std::vector<DDHost> dd_hosts;
};

FileConfig read_sdfs_config_file();

class invalid_cfg_file_line : public std::exception
{
protected:
	const std::string msg;

public:
	invalid_cfg_file_line(int line_no, const std::string& msg);
	const char* what() const noexcept override;
};

#endif /* __COMMON_FILE_CONFIG_H */
