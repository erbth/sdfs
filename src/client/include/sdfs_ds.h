#ifndef __CLIENT_SDFS_DS_H
#define __CLIENT_SDFS_DS_H

#include <vector>
#include <string>


namespace sdfs
{

namespace err
{
enum error_code : int
{
	SUCCESS = 0,
	IO,
	NOENT,
	INVAL,
	NOTDIR,
	NOSPC,
	NAMETOOLONG,
	ISDIR,
	NXIO
};
};

typedef size_t async_handle_t;
typedef void(*cb_async_finished_t)(async_handle_t handle, int status, void* arg);

struct ds_attr_t
{
	size_t size;
};


class DSClient final
{
protected:
	/* Pointer to implementation */
	void* client{};

public:
	DSClient(const std::vector<std::string>& portals);
	~DSClient();

	async_handle_t getattr(sdfs::ds_attr_t* dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	async_handle_t read(void* buf, size_t offset, size_t count,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	async_handle_t write(const void* buf, size_t offset, size_t count,
			sdfs::cb_async_finished_t cb_finished, void* arg);
};

std::string error_to_str(int code);

};

#endif /* __CLIENT_SDFS_DS_H */
