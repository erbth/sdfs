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
	for (auto& fi : fdinfos)
	{
		if (epoll_ctl(wfd.get_fd(), EPOLL_CTL_DEL, fi.fd, nullptr) < 0)
		{
			fprintf(stderr, "Failed to remove fd frome epoll instance "
					"during destructor\n");
		}
	}
}


void Epoll::add_fd(int fd, uint32_t events, fd_ready_cb_t cb)
{
	for (auto& fi : fdinfos)
	{
		if (fi.fd == fd)
			throw invalid_argument("fd already added to epoll instance");
	}

	fdinfo fi;
	fi.fd = fd;
	fi.cb = cb;

	struct epoll_event evt{};
	evt.events = events;
	evt.data.fd = fd;

	fdinfos.push_back(fi);

	try
	{
		check_syscall(
				epoll_ctl(wfd.get_fd(), EPOLL_CTL_ADD, fd, &evt),
				"epoll_ctl(add)");
	}
	catch (...)
	{
		fdinfos.pop_back();
		throw;
	}
}

void Epoll::change_events(int fd, uint32_t events)
{
	for (auto& fi : fdinfos)
	{
		if (fi.fd == fd)
		{
			struct epoll_event evt;
			evt.events = events;
			evt.data.fd = fd;

			check_syscall(
					epoll_ctl(wfd.get_fd(), EPOLL_CTL_MOD, fd, &evt),
					"epoll_ctl(mod)");
		}
	}

	throw invalid_argument("No such fd");
}

void Epoll::_remove_fd(int fd, bool ignore_unknown)
{
	auto i = fdinfos.begin();
	for (; i != fdinfos.end(); i++)
	{
		if (i->fd == fd)
			break;
	}

	if (i == fdinfos.end())
	{
		if (ignore_unknown)
			return

		throw invalid_argument("No such fd");
	}

	check_syscall(
			epoll_ctl(wfd.get_fd(), EPOLL_CTL_DEL, fd, nullptr),
			"epoll_ctl(del)");

	fdinfos.erase(i);
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

	for (int i = 0; i < ret; i++)
	{
		int fd = evts[i].data.fd;

		bool found = false;
		for (auto& fi : fdinfos)
		{
			if (fi.fd == fd)
			{
				fi.cb(fd, evts[i].events);

				found = true;
				break;
			}
		}

		if (!found)
			throw runtime_error("got event for unknown fd");
	}
}

int Epoll::get_fd()
{
	return wfd.get_fd();
}
