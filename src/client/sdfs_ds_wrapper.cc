#include <new>
#include "common/visibility.h"
#include "sdfs_ds_internal.h"
#include "sdfs_ds.h"

using namespace std;
using namespace std::literals;


#define DSCLIENT(X) reinterpret_cast<::DSClient*>(X)


namespace sdfs
{


SHLIB_EXPORTED DSClient::DSClient(const vector<string>& portals)
{
	client = new ::DSClient(portals);
}

SHLIB_EXPORTED DSClient::~DSClient()
{
	delete DSCLIENT(client);
	client = nullptr;
}

size_t SHLIB_EXPORTED DSClient::getattr(sdfs::ds_attr_t* dst,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	return DSCLIENT(client)->getattr(dst, cb_finished, arg);
}

size_t SHLIB_EXPORTED DSClient::read(void* buf, size_t offset, size_t count,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	return DSCLIENT(client)->read(buf, offset, count, cb_finished, arg);
}

size_t SHLIB_EXPORTED DSClient::write(const void* buf, size_t offset, size_t count,
		sdfs::cb_async_finished_t cb_finished, void* arg)
{
	return DSCLIENT(client)->write(buf, offset, count, cb_finished, arg);
}


std::string SHLIB_EXPORTED error_to_str(int code)
{
	switch(code)
	{
	case err::SUCCESS:
		return "success"s;

	case err::IO:
		return "IO error"s;

	case err::NOENT:
		return "No such file"s;

	case err::INVAL:
		return "Invalid arguments"s;

	case err::NOTDIR:
		return "Not a directory"s;

	case err::NOSPC:
		return "No space left"s;

	case err::NAMETOOLONG:
		return "Name too long"s;

	case err::ISDIR:
		return "Is a directory"s;

	case err::NXIO:
		return "No such device or address"s;

	default:
		return "Unknown error code"s;
	}
}


};
