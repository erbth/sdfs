#ifndef __COMMON_EVENTFD_H
#define __COMMON_EVENTFD_H

#include <functional>
#include "common/utils.h"
#include "common/epoll.h"

class EventFD final
{
public:
	using cb_t = std::function<void()>;

protected:
	Epoll& epoll;
	WrappedFD wfd;

	cb_t cb;

	void on_fd(int fd, uint32_t events);

public:
	EventFD(Epoll& epoll, cb_t cb);
	~EventFD();

	void signal();
};

#endif /* __COMMON_EVENTFD_H */
