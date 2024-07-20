#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include "utils.h"
#include "daemon_utils.h"

extern "C" {
#include <sys/socket.h>
#include <sys/un.h>
}

using namespace std;

void sdfs_systemd_notify(const std::string& msg)
{
	auto addr_str = secure_getenv("NOTIFY_SOCKET");
	if (!addr_str)
		return;

	if (addr_str[0] != '/' && addr_str[0] != '@')
		throw runtime_error("NOTIFY_SOCKET address not supported");

	if (msg.size() == 0)
		throw invalid_argument("msg must not be empty");

	sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;

	/* Ensure that there is enough room for terminating zero byte */
	auto addr_str_len = strlen(addr_str);
	if (addr_str_len >= sizeof(addr.sun_path))
		throw runtime_error("NOTIFY_SOCKET address too long");

	memcpy(addr.sun_path, addr_str, addr_str_len);

	/* Abstract socket */
	if (addr.sun_path[0] == '@')
		addr.sun_path[0] = 0;

	WrappedFD sock;
	sock.set_errno(
			socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0),
			"socket(NOTIFY_SOCKET)");

	check_syscall(
			connect(sock.get_fd(), (struct sockaddr*) &addr,
				offsetof(struct sockaddr_un, sun_path) + addr_str_len + 1),
			"connect(NOTIFY_SOCKET)");

	auto ret = write(sock.get_fd(), msg.c_str(), msg.size());
	if (ret != (ssize_t) msg.size())
		throw system_error(ret < 0 ? errno : EPROTO, generic_category(), "write(NOTIFY_SOCKET)");
}

void sdfs_systemd_notify_ready()
{
	sdfs_systemd_notify("READY=1"s);
}
