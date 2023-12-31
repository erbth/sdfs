#include "config.h"
#include "dd_ctx.h"

extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
}

using namespace std;


dd_ctx::dd_ctx(const string& device_file)
	: device_file(device_file)
{
}

dd_ctx::~dd_ctx()
{
	if (sock)
		epoll.remove_fd_ignore_unknown(sock.get_fd());
}

void dd_ctx::initialize_sock()
{
	bool have_port = false;

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT
	};

	for (port = SDFS_DD_PORT_START; port <= SDFS_DD_PORT_END; port++)
	{
		sock.set_errno(socket(AF_INET6, SOCK_STREAM, 0), "socket");

		addr.sin6_port = htons(port);

		if (bind(sock.get_fd(), (const sockaddr*) &addr, sizeof(addr)) < 0)
		{
			if (errno == EADDRINUSE)
				continue;
		}

		if (listen(sock.get_fd(), 5) < 0)
		{
			if (errno == EADDRINUSE)
				continue;

			throw system_error(errno, generic_category(), "listen");
		}

		have_port = true;
		break;
	}

	if (!have_port)
		throw runtime_error("Could not find a free port to listen on");

	epoll.add_fd(sock.get_fd(), EPOLLIN,
			bind(&dd_ctx::on_listen_sock, this, placeholders::_1, placeholders::_2));

	fprintf(stderr, "Listening on port %d\n", (int) port);
}

void dd_ctx::initialize_mgr()
{
}

void dd_ctx::initialize()
{
	/* Open device and read header */
	wfd.set_errno(open(device_file.c_str(), O_CLOEXEC | O_DIRECT | O_RDWR), "open");
	di = read_and_validate_device_header(wfd.get_fd());

	fprintf(stderr, "dd id: %u (gid: %s)\n", di.id, format_gid(di.gid).c_str());

	/* Find a free port and start listening */
	initialize_sock();

	/* Connect to sdfs-mgr and announce port */
	initialize_mgr();
}


void dd_ctx::on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		quit_requested = true;
}

void dd_ctx::on_listen_sock(int fd, uint32_t events)
{
	printf("new client\n");
}


void dd_ctx::on_epoll_ready(int res)
{
	if (res < 0)
		throw runtime_error("async poll on epoll fd failed");

	epoll.process_events(0);
}


void dd_ctx::main()
{
	io_uring.submit_poll(epoll.get_fd(), POLLIN,
			bind(&dd_ctx::on_epoll_ready, this, placeholders::_1));

	while (!quit_requested)
		io_uring.process_requests(true);
}


/* Controllers */
dd_client::dd_client(int fd)
	: wfd(fd)
{
}
