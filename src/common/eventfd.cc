#include "eventfd.h"

extern "C" {
#include <unistd.h>
#include <sys/eventfd.h>
}

using namespace std;


EventFD::EventFD(Epoll& epoll, cb_t cb)
	: epoll(epoll), cb(cb)
{
	wfd.set_errno(eventfd(0, EFD_CLOEXEC), "eventfd");

	epoll.add_fd(wfd.get_fd(), EPOLLIN, bind_front(&EventFD::on_fd, this));
}

EventFD::~EventFD()
{
	epoll.remove_fd(wfd.get_fd());
}


void EventFD::signal()
{
	uint64_t v = 1;
	check_syscall(write(wfd.get_fd(), &v, sizeof(v)), "write(eventfd)");
}


void EventFD::on_fd(int fd, uint32_t events)
{
	uint64_t v;
	check_syscall(read(wfd.get_fd(), &v, sizeof(v)), "read(eventfd)");

	cb();
}
