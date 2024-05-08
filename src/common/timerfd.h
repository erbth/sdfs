#ifndef __COMMON_TIMERFD_H
#define __COMMON_TIMERFD_H

#include <functional>
#include "common/utils.h"
#include "common/epoll.h"

class TimerFD final
{
public:
	using cb_t = std::function<void()>;

protected:
	Epoll& epoll;
	WrappedFD wfd;

	cb_t cb;

	void on_fd(int fd, uint32_t events);

public:
	TimerFD(Epoll& epoll, cb_t cb);
	~TimerFD();

	/* interval is measured in microseconds */
	void start(unsigned long interval);

	/* Missed events of a stopped TimerFD will still be executed */
	void stop();
};

#endif /* __COMMON_TIMERFD_H */
