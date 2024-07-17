#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <regex>
#include <deque>
#include <condition_variable>
#include "common/exceptions.h"
#include "common/file_config.h"
#include "common/utils.h"
#include "common/strformat.h"
#include "common/fixed_buffer.h"
#include "sync_call_utils.h"
#include "sdfs_ds.h"
#include "config.h"

using namespace std;
using namespace std::literals;
using namespace sdfs;


static_assert(sizeof(unsigned long) >= 8);


struct args_t final
{
	std::vector<std::string> portals;

	enum : int {
		OP_INFO = 1,
		OP_READ,
		OP_WRITE
	};
	int op;

	size_t offset;
	size_t size;
};

ssize_t parse_size_arg(char* v)
{
	cmatch m;
	if (!regex_match(v, m, regex("^([0-9][0-9]*)(\\.[0-9]*)?([kMGTP]?)$")))
		throw invalid_cmd_args("Invalid size specification");

	char* endptr = nullptr;
	auto s = m[1].str();
	auto a = strtoul(s.c_str(), &endptr, 10);
	if (s.size() == 0 || *endptr != '\0')
		throw invalid_cmd_args("Invalid size specification");

	s = m[2].str();
	double b = 0;

	if (s.size() > 1)
	{
		b = strtod(s.c_str(), &endptr);
		if (s.size() == 0 || *endptr != '\0')
			throw invalid_cmd_args("Invalid size specification");
	}

	unsigned long c = 1;
	s = m[3].str();
	if (s.size() > 0)
	{
		switch (s.c_str()[0])
		{
		case 'k':
			c = 1024;
			break;

		case 'M':
			c = 1024 * 1024;
			break;

		case 'G':
			c = 1024 * 1024 * 1024;
			break;

		case 'T':
			c = 1024 * 1024 * 1024 * 1024UL;
			break;

		case 'P':
			c = 1024 * 1024 * 1024UL * 1024 * 1024;
			break;

		default:
			break;
		}
	}

	return a*c + (unsigned long) floor(b*c);
}

args_t parse_args(int argc, char** argv)
{
	args_t args;

	int state = 0;
	int pos_cnt = 0;
	int pos_required = 1;

	for (int i = 1; i < argc; i++)
	{
		auto arg = argv[i];
		auto arglen = strlen(arg);

		switch (state)
		{
		case 0:
			if (arglen >= 2 && strncmp(arg, "--", 2) == 0)
			{
				/* Option */
				if (strcmp(arg, "--help") == 0)
				{
					throw cmd_args_help();
				}
				else if (strcmp(arg, "--portal") == 0)
				{
					state = 10000;
				}
				else
					throw invalid_cmd_args("Invalid option `"s + arg + "'"s);

				break;
			}

			pos_cnt++;

			if (pos_cnt == 1)
			{
				if (strcmp(arg, "info") == 0)
				{
					args.op = args_t::OP_INFO;
				}
				else if (strcmp(arg, "read") == 0)
				{
					args.op = args_t::OP_READ;
					pos_required = 3;
				}
				else if (strcmp(arg, "write") == 0)
				{
					args.op = args_t::OP_WRITE;
					pos_required = 2;
				}
				else
					throw invalid_cmd_args("Invalid operation `"s + arg + "'"s);
			}
			else if (pos_cnt == 2 && pos_required >= 2)
			{
				/* Offset */
				args.offset = parse_size_arg(arg);
			}
			else if (pos_cnt == 3 && pos_required >= 3)
			{
				/* Size */
				args.size = parse_size_arg(arg);
			}
			else
				throw invalid_cmd_args("too many positional arguments");

			break;

		case 10000:
			args.portals.push_back(arg);
			state = 0;
			break;

		default:
			throw runtime_error("error while parsing arguments");
		}
	}

	if (state != 0)
		throw invalid_cmd_args("option requires an argument");

	if (pos_cnt == 0)
		throw invalid_cmd_args("An operation must be specified");

	if (pos_cnt < pos_required)
		throw invalid_cmd_args("Missing positional argument for operation");

	if (args.portals.empty())
	{
		/* Read portals from config file */
		auto cfg = read_sdfs_config_file();
		for (auto& p : cfg.portals)
			args.portals.push_back(p);
	}

	return args;
}

void print_help()
{
	fprintf(stderr, R"help(SDFS block data storage tool of SDFS version %d.%d.%d

    Usage: sdfs_ds_tool [options] <operation> [arguments] [more options]

The following operations are available:
    info                     Print information about the block device

    read  [offset] [size]    Read data of the given size at the specified offset
                             and print it to stdout

    write [offset]           Read data from STDIN and write it at the specified
                             offset

The following options are available:
    --portal                 Specify a portal; multiple portals may be specified
                             for multipathing; if no portals are given, the
                             portals specified in the config file are used.

    --help                   Display this help text

Offsets and sizes might be specified with the suffices k,M,G,T,P, which multiply
with powers of 1024 accordingly.

)help",
		(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR, (int) SDFS_VERSION_PATCH);
}


void op_info(sdfs::DSClient& ds, const args_t& args)
{
	ds_attr_t attr;

	Synchronizer sync;
	ds.getattr(&attr, &Synchronizer::cb_finished, &sync);

	auto status = sync.wait();
	if (status != sdfs::err::SUCCESS)
		throw runtime_error("getattr failed: "s + sdfs::error_to_str(status));

	printf("Block data storage size: %s (%zu Bytes)\n",
			format_size_bin(attr.size).c_str(), (size_t) attr.size);
}


struct read_queue_entry final
{
	mutex m;
	condition_variable cv;
	size_t count{};

	bool finished = false;
	int result = -1;
};

void _cb_read_finished(sdfs::async_handle_t handle, int status, void* arg)
{
	auto rqe = reinterpret_cast<read_queue_entry*>(arg);

	{
		unique_lock lk(rqe->m);
		rqe->result = status;
		rqe->finished = true;
	}

	rqe->cv.notify_one();
}

void op_read(sdfs::DSClient& ds, const args_t& args)
{
	const size_t block_size = 1 * 1024 * 1024;

	/* Ring buffer */
	const size_t buf_size = block_size * 129;
	fixed_aligned_buffer buf(4096, buf_size);
	auto buf_ptr = buf.ptr();
	size_t buf_start = 0;
	size_t buf_end = 0;

	/* Request queue */
	deque<read_queue_entry> q;

	size_t cnt_scheduled = 0;
	size_t cnt_output = 0;

	while (cnt_output < args.size)
	{
		/* Schedule asynchronous reads as long as
		 *   * there is room in the buffer
		 *   * the size has not been reached */
		for (;;)
		{
			auto used = buf_start >= buf_end ?
				buf_start - buf_end :
				(buf_size - buf_end) + buf_start;

			if (used >= buf_size - block_size || cnt_scheduled == args.size)
				break;

			auto to_read = min(block_size, args.size - cnt_scheduled);

			auto& rqe = q.emplace_back();
			rqe.count = to_read;

			ds.read(buf_ptr + buf_start, args.offset + cnt_scheduled,
					to_read, _cb_read_finished, &rqe);

			buf_start = (buf_start + to_read) % buf_size;
			cnt_scheduled += to_read;
		}

		/* Check results and write to stdout */
		auto& rqe = q.front();
		unique_lock lk(rqe.m);
		while (!rqe.finished)
			rqe.cv.wait(lk);

		if (rqe.result != sdfs::err::SUCCESS)
			throw runtime_error("read failed: "s + sdfs::error_to_str(rqe.result));

		size_t pos = 0;
		while (pos < rqe.count)
		{
			auto ret = write(STDOUT_FILENO, buf_ptr + buf_end + pos, rqe.count - pos);
			if (ret < 0)
				throw system_error(errno, generic_category(), "write(stdout)");

			pos += ret;
		}

		cnt_output += rqe.count;

		buf_end = (buf_end + rqe.count) % buf_size;
		q.pop_front();
	}
}


struct write_queue_entry final
{
	mutex m;
	condition_variable cv;
	size_t count{};

	bool finished = false;
	int result = -1;
};

void _cb_write_finished(sdfs::async_handle_t handle, int status, void* arg)
{
	auto wqe = reinterpret_cast<write_queue_entry*>(arg);

	{
		unique_lock lk(wqe->m);
		wqe->result = status;
		wqe->finished = true;
	}

	wqe->cv.notify_one();
}

void op_write(sdfs::DSClient& ds, const args_t& args)
{
	bool eof = false;
	const size_t block_size = 1024 * 1024;

	/* Ring buffer */
	const size_t buf_size = block_size * 129;
	fixed_aligned_buffer buf(4096, buf_size);
	auto buf_ptr = buf.ptr();
	size_t buf_start = 0;
	size_t buf_end = 0;

	/* Request queue */
	deque<write_queue_entry> q;

	size_t offset = args.offset;

	while (!eof)
	{
		/* Read a block from stdin */
		size_t pos = 0;
		while (block_size - pos > 0)
		{
			auto ret = read(STDIN_FILENO, buf_ptr + buf_end + pos, block_size - pos);
			if (ret < 0)
				throw system_error(errno, generic_category(), "read(stdin)");

			if (ret == 0)
			{
				eof = true;
				break;
			}

			pos += ret;
		}


		/* Write block asynchronously */
		if (pos > 0)
		{
			auto& wqe = q.emplace_back();
			wqe.count = pos;

			ds.write(buf_ptr + buf_end, offset, pos, _cb_write_finished, &wqe);

			buf_end = (buf_end + pos) % buf_size;
			offset += pos;
		}


		/* Check results; wait until:
		 *   * ring buffer has at least one free entry
		 *   * ring buffer is empty in case of eof */
		for (;;)
		{
			auto used = buf_start >= buf_end ?
				buf_start - buf_end :
				(buf_size - buf_end) + buf_start;

			if ((used > block_size + 1 && !eof) || used == 0)
				break;

			auto& wqe = q.front();
			unique_lock lk(wqe.m);
			while (!wqe.finished)
				wqe.cv.wait(lk);

			if (wqe.result != sdfs::err::SUCCESS)
				throw runtime_error("write failed: "s + sdfs::error_to_str(wqe.result));

			buf_start = (buf_start + wqe.count) % buf_size;
			q.pop_front();
		}
	}
}


void main_exc(const args_t& args)
{
	sdfs::DSClient ds(args.portals);

	switch (args.op)
	{
	case args_t::OP_INFO:
		op_info(ds, args);
		break;

	case args_t::OP_READ:
		op_read(ds, args);
		break;

	case args_t::OP_WRITE:
		op_write(ds, args);
		break;

	default:
		throw runtime_error("Operation not implemented");
	}
}


int main(int argc, char** argv)
{
	try
	{
		main_exc(parse_args(argc, argv));
	}
	catch (const invalid_cmd_args& e)
	{
		fprintf(stderr, "%s\n", e.what());
		return EXIT_FAILURE;
	}
	catch (const cmd_args_help&)
	{
		print_help();
		return EXIT_FAILURE;
	}
	catch (const exception& e)
	{
		fprintf(stderr, "Error: %s\n", e.what());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
