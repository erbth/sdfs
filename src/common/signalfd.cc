#include "signalfd.h"

extern "C" {
#include <unistd.h>
#include <sys/signalfd.h>
#include <poll.h>
}

using namespace std;


SignalFD::SignalFD(const vector<int>& signals, Epoll& epoll, signal_cb_t cb)
	: epoll(epoll), cb(cb)
{
	sigset_t sigset;
	sigemptyset(&sigset);

	for (auto& s : signals)
		sigaddset(&sigset, s);

	wfd.set_errno(signalfd(-1, &sigset, SFD_CLOEXEC), "signalfd");
	epoll.add_fd(wfd.get_fd(), EPOLLIN,
			bind(&SignalFD::on_sfd, this, placeholders::_1, placeholders::_2));

	try
	{
		check_syscall(sigprocmask(SIG_BLOCK, &sigset, nullptr), "sigprocmask");
	}
	catch (...)
	{
		epoll.remove_fd(wfd.get_fd());
		throw;
	}
}

SignalFD::~SignalFD()
{
	epoll.remove_fd(wfd.get_fd());
}

void SignalFD::on_sfd(int fd, uint32_t events)
{
	struct signalfd_siginfo fdsi;
	if (read(wfd.get_fd(), &fdsi, sizeof(fdsi)) != sizeof(fdsi))
		throw system_error(errno, generic_category(), "read(signalfd)");

	cb(fdsi.ssi_signo);
}

void SignalFD::check(int timeout)
{
	struct pollfd pfd = {
		.fd = wfd.get_fd(),
		.events = POLLIN,
		.revents = 0
	};

	if (check_syscall(poll(&pfd, 1, timeout), "poll(signalfd)") > 0)
		on_sfd(wfd.get_fd(), EPOLLIN);
}
