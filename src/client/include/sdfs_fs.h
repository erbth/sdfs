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
};

};

#endif /* _SDFS_FS_H */
