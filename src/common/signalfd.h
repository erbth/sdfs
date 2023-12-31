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
};

#endif /* __COMMON_SIGNAL_FD */
