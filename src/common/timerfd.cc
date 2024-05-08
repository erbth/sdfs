#include "timerfd.h"

extern "C" {
#include <unistd.h>
#include <sys/timerfd.h>
}

using namespace std;


TimerFD::TimerFD(Epoll& epoll, cb_t cb)
	: epoll(epoll), cb(cb)
{
	wfd.set_errno(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC), "timerfd_create");

	epoll.add_fd(wfd.get_fd(), EPOLLIN, bind_front(&TimerFD::on_fd, this));
}

TimerFD::~TimerFD()
{
	epoll.remove_fd(wfd.get_fd());
}


void TimerFD::start(unsigned long interval)
{
	auto seconds = interval / 1000000;
	auto nanoseconds = (interval % 1000000) * 1000UL;

	struct itimerspec its{};
	its.it_interval.tv_sec = seconds;
	its.it_interval.tv_nsec = nanoseconds;
	its.it_value.tv_sec = seconds;
	its.it_value.tv_nsec = nanoseconds;

	check_syscall(timerfd_settime(wfd.get_fd(), 0, &its, nullptr),
			"timerfd_settime");
}

void TimerFD::stop()
{
	struct itimerspec its{};
	check_syscall(timerfd_settime(wfd.get_fd(), 0, &its, nullptr),
			"timerfd_settime");
}


void TimerFD::on_fd(int fd, uint32_t events)
{
	uint64_t v;
	check_syscall(read(wfd.get_fd(), &v, sizeof(v)), "read(timerfd)");

	cb();
}
