#ifndef __COMMON_SIGNAL_FD
#define __COMMON_SIGNAL_FD

#include <csignal>
#include <functional>
#include <vector>
#include "common/utils.h"
#include "common/epoll.h"

class SignalFD final
{
public:
	using signal_cb_t = std::function<void(int signo)>;

protected:
	WrappedFD wfd;
	Epoll& epoll;

	signal_cb_t cb;

	void on_sfd(int fd, uint32_t events);

public:
	SignalFD(const std::vector<int>& signals, Epoll& epoll, signal_cb_t cb);
	~SignalFD();

	/* Check if the FD is ready and read signals if it is the case. Sometimes
	 * one might want to use the FD outside of the main loop, e.g. during
	 * initialization. This can be acomplished with this method. timeout is in
	 * milliseconds, 0 means do not block, and a negative value block
	 * indefinitely. */
	void check(int timeout);
};

#endif /* __COMMON_SIGNAL_FD */
