/** NOTE: It would be better to use liburing here. However on Debian Bullseye
 * only an older version is packaged. */
#ifndef __COMMON_IO_URING_H
#define __COMMON_IO_URING_H

#include <memory>
#include <functional>
#include "common/utils.h"

extern "C" {
#include <poll.h>
}

static_assert(sizeof(short) == 2);
static_assert(sizeof(int) == 4);


struct IOUringCtx;

class IOUring final
{
public:
	using complete_cb_t = std::function<void(int res)>;

protected:
	std::unique_ptr<IOUringCtx> ctx;

public:
	IOUring(unsigned entries);
	~IOUring();

	void submit_poll(int fd, short events, complete_cb_t cb);

	/* Similar to pwritev2 */
	void queue_writev(int fd, const struct iovec *iov, int iovcnt,
			off_t offset, int flags, complete_cb_t cb);

	/* NOTE: If this fails (with an exception), the queued requests will not be
	 * deleted */
	void submit();

	/* If block is true and no requests are finished yet, block until a request
	 * becomes available */
	void process_requests(bool block);
};

#endif /* __COMMON_IO_URING_H */
