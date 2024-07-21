/* Utility functions and definitions for filesystem code */
#ifndef __CLIENT_FS_UTILS_H
#define __CLIENT_FS_UTILS_H

#include <vector>
#include <tuple>
#include <string>

struct superblock_t
{
	size_t raw_size{};
	size_t block_count{};
	size_t inode_count{};

	size_t inode_directory_size{};
	size_t inode_allocator_size{};
	size_t block_allocator_size{};

	/* Values below this line are calculated */
	size_t usable_size{};

	size_t inode_directory_offset{};
	size_t inode_allocator_offset{};
	size_t block_allocator_offset{};
};

struct inode_t
{
	/* Actual inode data */
	enum inode_type : unsigned
	{
		TYPE_FREE = 0,
		TYPE_FILE = 1,
		TYPE_DIRECTORY = 2,
		TYPE_EXTENSION = 3
	} type = TYPE_FREE;

	size_t nlink = 0;
	size_t size = 0;

	/* In microseconds */
	unsigned long mtime{};


	/* For files */
	struct allocation {
		size_t offset;
		size_t size;

		inline allocation()
		{
		}

		inline allocation(size_t offset, size_t size)
			: offset(offset), size(size)
		{
		}
	};
	std::vector<allocation> allocations;

	size_t get_allocated_size() const;


	/* For directories (name, inode, type) */
	std::vector<std::tuple<std::string, unsigned long, unsigned>> files;

	bool enough_space_for_file(const std::string& name) const;


	/* The buffer needs to be 4096 bytes long */
	void serialize(char* buf) const;
	void parse(const char* buf);
};


/* @param raw_size is used as integrity check */
superblock_t parse_superblock(size_t raw_size, const char* buf);
void superblock_calculate_offsets(superblock_t& sb);

#endif /* __CLIENT_FS_UTILS_H */
