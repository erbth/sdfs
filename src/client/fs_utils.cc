#include <cstring>
#include "config.h"
#include "fs_utils.h"
#include "common/serialization.h"
#include "common/exceptions.h"
#include "common/utils.h"

using namespace std;


superblock_t parse_superblock(size_t raw_size, const char* buf)
{
	/* For simplicity, require the raw size to be aligned (will always be the
	 * case in sdfs, anyway) */
	if (raw_size % 4096)
		throw runtime_error("raw size is not a multiple of 4096");

	superblock_t sb;

	auto mlen = strlen(SDFS_FS_SB_MAGIC);

	if (memcmp(buf + 4096 - mlen, SDFS_FS_SB_MAGIC, mlen) != 0)
		throw invalid_superblock("invalid magic");

	auto ptr = buf;

	sb.raw_size = ser::sread_u64(ptr);
	sb.block_count = ser::sread_u64(ptr);
	sb.inode_count = ser::sread_u64(ptr);

	sb.inode_directory_size = ser::sread_u64(ptr);
	sb.inode_allocator_size = ser::sread_u64(ptr);
	sb.block_allocator_size = ser::sread_u64(ptr);

	if (sb.raw_size != raw_size)
		throw invalid_superblock("raw size mismatch");


	/* Calculate and verify usable size */
	sb.usable_size = sb.block_count * 1024 * 1024UL;
	auto sum = 4096 + sb.block_allocator_size + sb.inode_allocator_size +
		sb.inode_directory_size + sb.usable_size;

	if (sum > sb.raw_size)
		throw invalid_superblock("total data is larger than the raw size");


	/* Calculate offsets */
	superblock_calculate_offsets(sb);

	return sb;
}

void superblock_calculate_offsets(superblock_t& sb)
{
	sb.block_allocator_offset = sb.raw_size - 4096 - sb.block_allocator_size;
	sb.inode_allocator_offset = sb.block_allocator_offset - sb.inode_allocator_size;
	sb.inode_directory_offset = sb.inode_allocator_offset - sb.inode_directory_size;
}


size_t inode_t::get_allocated_size() const
{
	size_t s = 0;
	for (auto& a : allocations)
		s += a.size;

	return s;
}

bool inode_t::enough_space_for_file(const std::string& name) const
{
	size_t entry_size = 0;
	for (const auto& [f_name, f_node_id, f_type] : files)
		entry_size += 1 + f_name.size() + 8 + 1;

	entry_size += 1 + name.size() + 8 + 1;

	return entry_size <= 3480;
}

void inode_t::serialize(char* buf) const
{
	memset(buf, 0, 4096);
	auto ptr = buf;

	ser::swrite_u8(ptr, type);

	/* For extension-inodes */
	ser::swrite_u64(ptr, 0);

	if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		ser::swrite_u64(ptr, nlink);
		ser::swrite_u64(ptr, size);
		ser::swrite_u64(ptr, mtime);

		/* 1+8+3*8 = 33; reserve first 256 bytes */
		ptr = buf + 256;

		if (type == TYPE_FILE)
		{
			if (allocations.size() > 240)
				throw invalid_argument("at most 240 allocations per inode are supported");

			for (const auto& a : allocations)
			{
				ser::swrite_u64(ptr, a.offset);
				ser::swrite_u64(ptr, a.size);
			}
		}
		else
		{
			size_t entry_size = 0;
			for (const auto& [name, f_node_id, f_type] : files)
			{
				if (name.size() > 255 || name.size() == 0)
					throw invalid_argument("filename too long or empty");

				if (f_node_id == 0)
					throw invalid_argument("dir entry node_id is 0");

				entry_size += 1 + name.size() + 8 + 1;

				if (entry_size > 3480)
					throw invalid_argument("file reference data structure too large");

				ser::swrite_u8(ptr, name.size());
				memcpy(ptr, name.c_str(), name.size());
				ptr += name.size();
				ser::swrite_u64(ptr, f_node_id);
				ser::swrite_u8(ptr, f_type);
			}
		}
	}
}

void inode_t::parse(const char* buf)
{
	auto ptr = buf;
	type = (inode_t::inode_type) ser::sread_u8(ptr);

	/* For extension-inodes */
	ser::sread_u64(ptr);

	if (type == TYPE_FREE)
	{
	}
	else if (type == TYPE_FILE || type == TYPE_DIRECTORY)
	{
		nlink = ser::sread_u64(ptr);
		size = ser::sread_u64(ptr);
		mtime = ser::sread_u64(ptr);

		ptr = buf + 256;

		if (type == TYPE_FILE)
		{
			allocations.clear();

			for (;;)
			{
				allocation a;
				a.offset = ser::sread_u64(ptr);
				a.size = ser::sread_u64(ptr);
				if (a.size == 0)
					break;

				allocations.push_back(a);
			}
		}
		else
		{
			files.clear();

			for (;;)
			{
				char buf[256];
				uint8_t namesz = ser::sread_u8(ptr);
				if (namesz == 0)
					break;

				memcpy(buf, ptr, namesz);
				ptr += namesz;

				buf[min(namesz, (uint8_t) 255)] = '\0';

				auto f_node_id = ser::sread_u64(ptr);
				if (f_node_id == 0)
					break;

				auto f_type = ser::sread_u8(ptr);

				files.emplace_back(string(buf, namesz), f_node_id, f_type);
			}
		}
	}
	else
	{
		throw invalid_argument("Invalid inode type: `" + to_string(type) + "'");
	}
}
