#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include "sdfs_ds_internal.h"
#include "fs_utils.h"
#include "config.h"
#include "common/exceptions.h"
#include "common/file_config.h"
#include "common/strformat.h"
#include "common/serialization.h"

using namespace std;
using namespace std::literals;


struct args_t final
{
	vector<string> portals;

	bool format = false;
	bool force = false;
};


size_t get_raw_size(sdfs::DSClient& dsc)
{
	io_promise iop;

	sdfs::ds_attr_t ds_attr;
	dsc.getattr(&ds_attr, cb_io_promise, &iop);
	if (iop.wait() != sdfs::err::SUCCESS)
		throw system_error(EIO, generic_category());

	return ds_attr.size;
}

superblock_t read_sb(sdfs::DSClient& dsc, size_t raw_size)
{
	superblock_t sb;
	io_promise iop;

	if (raw_size < 4096)
		throw runtime_error("raw size of block storage too small");

	/* Read superblock */
	char buf[4096];
	dsc.read(buf, raw_size - 4096, 4096, cb_io_promise, &iop);
	if (iop.wait() != sdfs::err::SUCCESS)
		throw system_error(EIO, generic_category());

	return parse_superblock(raw_size, buf);
}

void write_zero(sdfs::DSClient& dsc, size_t offset, size_t count)
{
	const size_t block_size = 1024 * 1024;
	char buf[block_size];
	memset(buf, 0, block_size);

	io_promise iop;

	for (size_t i = 0; i < count; i += block_size)
	{
		auto to_write = min(block_size, count - i);

		dsc.write(buf, offset + i, to_write, cb_io_promise, &iop);
		if (iop.wait() != sdfs::err::SUCCESS)
			throw system_error(EIO, generic_category());

		if (i % (block_size * 100) == 0)
		{
			printf("\r%5.1f%%", (double) i / count * 100);
			fflush(stdout);
		}
	}

	printf("\r100.0%%\n");
}

void write_data(sdfs::DSClient& dsc, const char* buf, size_t offset, size_t count)
{
	const size_t block_size = 1024 * 1024;

	io_promise iop;

	for (size_t i = 0; i < count; i += block_size)
	{
		auto to_write = min(block_size, count - i);

		dsc.write(buf + i, offset + i, to_write, cb_io_promise, &iop);
		if (iop.wait() != sdfs::err::SUCCESS)
			throw system_error(EIO, generic_category());
	}
}


void print_sb(const superblock_t& sb)
{
	printf(R"info(Superblock:
    raw size: %s (%zu bytes)

    block count: %zu
    inode count: %zu

    block allocator size: %s (%zu bytes)
    inode allocator size: %s (%zu bytes)
    inode directory size: %s (%zu bytes)
    usable size:          %s (%zu bytes)

    inode directory offset: %zu bytes
    inode allocator offset: %zu bytes
    block allocator offset: %zu bytes

)info",
			format_size_si(sb.raw_size).c_str(), sb.raw_size,
			sb.block_count,
			sb.inode_count,

			format_size_si(sb.block_allocator_size).c_str(), sb.block_allocator_size,
			format_size_si(sb.inode_allocator_size).c_str(), sb.inode_allocator_size,
			format_size_si(sb.inode_directory_size).c_str(), sb.inode_directory_size,
			format_size_si(sb.usable_size).c_str(), sb.usable_size,

			sb.inode_directory_offset,
			sb.inode_allocator_offset,
			sb.block_allocator_offset
	);
}


args_t parse_args(int argc, char** argv)
{
	args_t args;

	int state = 0;

	for (int i = 1; i < argc; i++)
	{
		auto arg = argv[i];
		auto arglen = strlen(arg);

		switch (state)
		{
		case 0:
			if (arglen >= 2 && strncmp(arg, "--", 2) == 0)
			{
				if (strcmp(arg, "--help") == 0)
				{
					throw cmd_args_help();
				}
				else if (strcmp(arg, "--portal") == 0)
				{
					state = 1000;
				}
				else if (strcmp(arg, "--format") == 0)
				{
					if (args.format)
						throw invalid_cmd_args("`--format' specified multiple times");
					args.format = true;
				}
				else if (strcmp(arg, "--force") == 0)
				{
					if (args.force)
						throw invalid_cmd_args("`--force' specified multiple times");
					args.force = true;
				}
				else
				{
					throw invalid_cmd_args("Invalid option `"s + arg + "'"s);
				}
			}
			else
			{
				throw invalid_cmd_args("Invalid argument: `"s + arg + "'"s);
			}
			break;

		case 1000:
			args.portals.push_back(arg);
			state = 0;
			break;

		default:
			throw runtime_error("Error while parsing arguments");
		}
	}

	if (state != 0)
		throw invalid_cmd_args("Option requires an argument");

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
	fprintf(stderr, R"help(sdfs-mkfs of SDFS version %d.%d.%d

    usage: sdfs-mkfs [options]

The following options are available:
    --portal                 Specify a portal; multiple portals may be specified
                             for multipathing; if no portals are given, the
                             portals specified in the config file are used.

    --format                 By default only filesystem information is
                             displayed. Use this switch to format the
                             filesystem.

    --force                  By default an existing filesystem will not be
                             overwritten. Use this switch to request overwriting
                             an existing filesystem.

    --help                   Display this help text
)help",
			(int) SDFS_VERSION_MAJOR, (int) SDFS_VERSION_MINOR,
			(int) SDFS_VERSION_PATCH);
}


int main_exc(args_t args)
{
	/* Connect to cluster */
	sdfs::DSClient dsc(args.portals);

	/* Read raw storage size */
	size_t raw_size = get_raw_size(dsc);

	printf("Block storage size: %s (%zu bytes)\n\n",
			format_size_si(raw_size).c_str(), raw_size);


	/* Try to read superblock */
	bool have_sb = false;
	{
		superblock_t sb;

		try
		{
			sb = read_sb(dsc, raw_size);
			print_sb(sb);
			have_sb = true;
		}
		catch (const invalid_superblock& e)
		{
			printf("Invalid filesystem: %s\n", e.what());
		}
	}

	if (!args.format)
		return EXIT_SUCCESS;

	if (have_sb && !args.force)
	{
		printf("Not overwriting existing filesystem.\n"
				"Specify `--force' to overwrite the existing filesystem.\n");
		return EXIT_FAILURE;
	}

	printf("Formatting filesystem...\n");

	/* Build superblock */
	superblock_t sb;

	if (raw_size % 4096)
		throw runtime_error("raw size is not a multiple of 4096");

	sb.raw_size = raw_size;

	/* Start with maximum block count for metadata size calculation */
	sb.block_count = sb.raw_size / (1024 * 1024);

	/* min(1e6, 5% of raw size) */
	sb.inode_count = min(sb.raw_size / (20 * 4096), 1000 * 1000UL);

	sb.inode_directory_size = sb.inode_count * 4096;
	sb.inode_allocator_size = align_up(4096UL, (sb.inode_count + 7) / 8);
	sb.block_allocator_size = align_up(4096UL, (sb.block_count + 7) / 8);

	size_t metadata_size = 4096 + sb.inode_directory_size +
		sb.inode_allocator_size + sb.block_allocator_size;

	/* Adjust block count to actually usable value */
	sb.block_count = (sb.raw_size - metadata_size)  / (1024 * 1024);

	/* Serialize suberblock */
	char sb_buf[4096];
	auto sb_ptr = sb_buf;

	ser::swrite_u64(sb_ptr, sb.raw_size);
	ser::swrite_u64(sb_ptr, sb.block_count);
	ser::swrite_u64(sb_ptr, sb.inode_count);

	ser::swrite_u64(sb_ptr, sb.inode_directory_size);
	ser::swrite_u64(sb_ptr, sb.inode_allocator_size);
	ser::swrite_u64(sb_ptr, sb.block_allocator_size);

	superblock_calculate_offsets(sb);

	/* Magic */
	auto mlen = strlen(SDFS_FS_SB_MAGIC);
	memcpy(sb_buf + 4096 - mlen, SDFS_FS_SB_MAGIC, mlen);


	printf("Clearing metadata regions...\n");
	write_zero(dsc, sb.raw_size - metadata_size, metadata_size);


	printf("Writing root directory...\n");

	inode_t root;
	root.type = inode_t::TYPE_DIRECTORY;
	root.nlink = 2;
	root.size = 2;
	root.mtime = get_wt_now();

	root.files.emplace_back(".", 1);
	root.files.emplace_back("..", 1);

	char buf[4096];
	root.serialize(buf);

	write_data(dsc, buf, sb.inode_directory_offset + 4096, 4096);

	/* Mark inode allocated */
	memset(buf, 0, 4096);
	buf[0] = 0x02;
	write_data(dsc, buf, sb.inode_allocator_offset, 4096);


	printf("Writing superblock...\n");
	write_data(dsc, sb_buf, raw_size - 4096, 4096);


	printf("finished.\n\n");

	sb = read_sb(dsc, raw_size);
	print_sb(sb);

	return EXIT_SUCCESS;
}


int main(int argc, char** argv)
{
	try
	{
		return main_exc(parse_args(argc, argv));
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
}
