#include <cstdio>
#include <stdexcept>
#include "utils.h"
#include "epoll.h"

using namespace std;


Epoll::Epoll()
{
	wfd.set_errno(epoll_create1(EPOLL_CLOEXEC), "epoll_create1");
}

Epoll::~Epoll()
{
	for (auto& [fd,cb] : cbs)
	{
		if (epoll_ctl(wfd.get_fd(), EPOLL_CTL_DEL, fd, nullptr) < 0)
		{
			fprintf(stderr, "Failed to remove fd frome epoll instance "
					"during destructor\n");
		}
	}
}


void Epoll::add_fd(int fd, uint32_t events, fd_ready_cb_t cb)
{
	auto [i,inserted] = cbs.insert({fd, cb});
	if (!inserted)
			throw invalid_argument("fd already added to epoll instance");

	try
	{
		struct epoll_event evt{};
		evt.events = events;
		evt.data.fd = fd;

		check_syscall(
				epoll_ctl(wfd.get_fd(), EPOLL_CTL_ADD, fd, &evt),
				"epoll_ctl(add)");
	}
	catch (...)
	{
		cbs.erase(i);
		throw;
	}
}

void Epoll::change_events(int fd, uint32_t events)
{
	if (cbs.find(fd) == cbs.end())
		throw invalid_argument("No such fd");

	struct epoll_event evt{};
	evt.events = events;
	evt.data.fd = fd;

	check_syscall(
			epoll_ctl(wfd.get_fd(), EPOLL_CTL_MOD, fd, &evt),
			"epoll_ctl(mod)");
}

void Epoll::_remove_fd(int fd, bool ignore_unknown)
{
	auto i = cbs.find(fd);
	if (i == cbs.end())
	{
		if (ignore_unknown)
			return;

		throw invalid_argument("No such fd");
	}

	check_syscall(
			epoll_ctl(wfd.get_fd(), EPOLL_CTL_DEL, fd, nullptr),
			"epoll_ctl(del)");

	cbs.erase(i);
}

void Epoll::remove_fd(int fd)
{
	_remove_fd(fd, false);
}

void Epoll::remove_fd_ignore_unknown(int fd)
{
	_remove_fd(fd, true);
}

void Epoll::process_events(int timeout)
{
	struct epoll_event evts[128];

	auto ret = check_syscall(
			epoll_wait(wfd.get_fd(), evts, sizeof(evts) / sizeof(evts[0]), timeout),
			"epoll_wait");

	/* Ensure fdinfos can be changed during cb (i.e. when adding or removing
	 * fds) */
	for (int i = 0; i < ret; i++)
	{
		int fd = evts[i].data.fd;

		/* This is fatal because we cannot remove the fd and a newly opened fd
		 * might get the same number */
		auto ic = cbs.find(fd);
		if (ic == cbs.end())
			throw runtime_error("Got event for unmonitored fd");

		/* Ensure that the fd can be deleted in the callback */
		auto cb = ic->second;

		if (cb)
			cb(fd, evts[i].events);
	}
}

int Epoll::get_fd()
{
	return wfd.get_fd();
}
