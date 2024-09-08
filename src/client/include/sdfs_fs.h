#ifndef _SDFS_FS_H
#define _SDFS_FS_H

#include <vector>
#include <string>
#include <sdfs_ds.h>

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
}


namespace sdfs
{


struct fs_attr_t
{
	/* 'traditional statfs' parameters */
	size_t size;
	size_t used;

	size_t inodes;
	size_t inodes_used;
};

struct dir_entry_t
{
	unsigned long ino;
	std::string name;
};


class FSClient final
{
protected:
	/* Pointer to implementation */
	void* client{};

public:
	FSClient(const std::vector<std::string>& portals);
	~FSClient();

	async_handle_t getfsattr(fs_attr_t* dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t lookup(unsigned long parent_ino, const char* name, struct stat* dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t getattr(unsigned long ino, struct stat& dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t readdir(unsigned long ino, std::vector<dir_entry_t>& dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t mkdir(unsigned long parent, const char* name, struct stat& dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t rmdir(unsigned long parent, const char* name,
			bool auto_free_inode, unsigned long* ino,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t create(unsigned long parent, const char* name, struct stat& dst,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t unlink(unsigned long parent, const char* name,
			bool auto_free_inode, unsigned long* ino,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t free_inode_explicit(unsigned long ino,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t read(
			unsigned long ino, size_t offset, size_t size, size_t& dst_size, char* buf,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t write(
			unsigned long ino, off_t offset, size_t size, const char* buf,
			cb_async_finished_t cb_finished, void* arg);

	async_handle_t truncate(
			unsigned long ino,
			cb_async_finished_t cb_finished, void* arg);
};

};

#endif /* _SDFS_FS_H */
