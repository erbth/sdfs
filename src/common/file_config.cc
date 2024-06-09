#include <algorithm>
#include <string>
#include <filesystem>
#include <fstream>
#include <regex>
#include "config.h"
#include "file_config.h"

using namespace std;
namespace fs = std::filesystem;


string strip_string(const string& s)
{
	smatch m;
	if (!regex_match(s, m, regex("^\\s*(.*)$")))
		throw runtime_error("regex did not match string");

	return m[1];
}

FileConfig read_sdfs_config_file()
{
	FileConfig cfg;

	ifstream s(SDFS_CONFIG_FILE);
	if (!s)
		throw runtime_error("Failed to open config file");

	string line;
	int state = 0;

	int line_no = 0;
	while (getline(s, line))
	{
		line_no++;

		smatch m;
		if (!regex_match(line, m, regex("^([^#]*?)\\s*(#.*)?$")))
			throw runtime_error("regex did not match line");

		line = m[1];
		if (line.size() == 0)
			continue;

		if (regex_match(line, regex("^\\S.*")))
			state = 0;

		if (state == 0)
		{
			if (line == "portals:")
			{
				state = 1;
			}
			else if (line == "dd_hosts:")
			{
				state = 2;
			}
			else if (line == "dds:")
			{
				state = 3;
			}
			else
			{
				throw invalid_cfg_file_line(line_no, "unknown section");
			}
		}
		else if (state == 1)
		{
			line = strip_string(line);

			smatch m2;
			if (!regex_match(line, m2, regex("^(\\S+)$")))
			{
				throw invalid_cfg_file_line(line_no,
						"invalid portal specification");
			}

			cfg.portals.push_back(m2[1]);
		}
		else if (state == 2)
		{
			line = strip_string(line);

			if (regex_match(line, regex(".*\\s.*")))
			{
				throw invalid_cfg_file_line(line_no,
						"host addresses must not contain whitespace");
			}

			FileConfig::DDHost desc;
			desc.addr_str = line;
			cfg.dd_hosts.push_back(desc);
		}
		else if (state == 3)
		{
			smatch m2;
			if (!regex_match(line, m2, regex("^\\s*([0-9]+)\\s+([0-9a-fA-F]{32}+)$")))
			{
				throw invalid_cfg_file_line(line_no,
						"invalid dd specification");
			}

			auto id = strtoul(m2[1].str().c_str(), nullptr, 10);
			if (id < 1)
			{
				throw invalid_cfg_file_line(line_no,
						"dd ids must be >= 1");
			}

			FileConfig::DD desc;
			desc.id = id;
			desc.gid = m2[2];
			cfg.dds.push_back(desc);
		}
		else
		{
			throw runtime_error("cfg file section parser not implemented yet");
		}
	}

	/* Sort lists */
	sort(cfg.dds.begin(), cfg.dds.end(),
			[](const auto& a, const auto& b) {
				return a.id < b.id;
			});

	return cfg;
}


invalid_cfg_file_line::invalid_cfg_file_line(int line_no, const string& msg)
	: msg("Error in config file on line " + to_string(line_no) + ": " + msg)
{
}

const char* invalid_cfg_file_line::what() const noexcept
{
	return msg.c_str();
}
