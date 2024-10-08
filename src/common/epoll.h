#ifndef __COMMON_EPOLL_H
#define __COMMON_EPOLL_H

#include <map>
#include <functional>
#include <mutex>
#include "common/utils.h"

extern "C" {
#include <sys/epoll.h>
}

/* Events for successfully removed fds (i.e. remov_fd/remove_fd_ignore_unknown
 * did not throw an exception) will never be reported */
class Epoll final
{
public:
	using fd_ready_cb_t = std::function<void(int, uint32_t)>;

protected:
	std::mutex m;
	WrappedFD wfd;

	std::map<int, fd_ready_cb_t> cbs;

	void cleanup();

	void _remove_fd(int fd, bool ignore_unknown);

public:
	Epoll();
	~Epoll();

	/* If this function throws, the cb will not have been added */
	void add_fd(int fd, uint32_t events, fd_ready_cb_t cb);

	void change_events(int fd, uint32_t events);
	void remove_fd(int fd);
	void remove_fd_ignore_unknown(int fd);

	/* timeout is in milliseconds; 0 does not wait at all and -1 waits
	 * indefinitely */
	void process_events(int timeout);

	int get_fd();
};

#endif /* __COMMON_EPOLL_H */
