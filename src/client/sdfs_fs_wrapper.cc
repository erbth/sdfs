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
		bool auto_free_inode, unsigned long* ino,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->rmdir(parent, name, auto_free_inode, ino, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::create(
		unsigned long parent, const char* name, struct stat& dst,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->create(parent, name, dst, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::unlink(
		unsigned long parent, const char* name,
		bool auto_free_inode, unsigned long* ino,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->unlink(parent, name, auto_free_inode, ino, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::free_inode_explicit(unsigned long ino,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->free_inode_explicit(ino, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::read(
		unsigned long ino, size_t offset, size_t size, size_t& dst_size, char* buf,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->read(ino, offset, size, dst_size, buf,
			cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::write(
		unsigned long ino, size_t offset, size_t size, const char* buf,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->write(ino, offset, size, buf, cb_finished, arg);
}

async_handle_t SHLIB_EXPORTED FSClient::truncate(
		unsigned long ino,
		cb_async_finished_t cb_finished, void* arg)
{
	return FSCLIENT(client)->truncate(ino, cb_finished, arg);
}


}
