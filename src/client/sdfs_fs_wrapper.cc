#include <new>
#include "common/visibility.h"
#include "sdfs_fs_internal.h"
#include "sdfs_fs.h"

using namespace std;
using namespace std::literals;


#define FSCLIENT(X) reinterpret_cast<::FSClient*>(X)


namespace sdfs
{


SHLIB_EXPORTED FSClient::FSClient(const vector<string>& portals)
{
	client = new ::FSClient(portals);
}

SHLIB_EXPORTED FSClient::~FSClient()
{
	delete FSCLIENT(client);
	client = nullptr;
}

async_handle_t SHLIB_EXPORTED FSClient::getfsattr(fs_attr_t* dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->getfsattr(dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::lookup(
		unsigned long parent_ino, const char* name, struct stat* dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->lookup(parent_ino, name, dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::getattr(
		unsigned long ino, struct stat& dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->getattr(ino, dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::readdir(
		unsigned long ino, vector<dir_entry_t>& dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->readdir(ino, dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::mkdir(
		unsigned long parent, const char* name, struct stat& dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->mkdir(parent, name, dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::rmdir(
		unsigned long parent, const char* name,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->rmdir(parent, name, cb_finished, arg);
}


}
