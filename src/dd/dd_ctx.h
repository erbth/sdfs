#ifndef __DD_CTX_H
#define __DD_CTX_H

#include <string>
#include <memory>
#include <vector>
#include <array>
#include <list>
#include <optional>
#include <queue>
#include <variant>
#include <stdexcept>
#include "common/utils.h"
#include "common/io_uring.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/fixed_buffer.h"
#include "common/dynamic_buffer.h"
#include "common/prot_dd.h"
#include "utils.h"


/* Must be a multiple of 4096 */
#define MAX_IO_REQ_SIZE (1024 * 1024ULL)


static_assert(sizeof(int) >= 4);


struct disk_io_req;

struct dd_queued_msg final
{
	using buf_t = std::variant<dynamic_buffer, dynamic_aligned_buffer, disk_io_req*>;

	buf_t vbuf;
	const size_t msg_len;

	inline dd_queued_msg(
			buf_t&& vbuf,
			size_t msg_len)
		: vbuf(std::move(vbuf)), msg_len(msg_len)
	{
	}

	const char* buf_ptr();

	inline void return_buffer(dynamic_aligned_buffer_pool& pool)
	{
		if (std::holds_alternative<dynamic_aligned_buffer>(vbuf))
			pool.return_buffer(std::move(std::get<dynamic_aligned_buffer>(vbuf)));
	}

	~dd_queued_msg();
};


/* Connections from controllers */
struct dd_client final
{
	/* After a client was removed from the list but is still kept alive through
	 * a shared_ptr */
	bool invalid = false;

	WrappedFD wfd;

	/* Receive messages */
	dynamic_aligned_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Send messages */
	std::queue<dd_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


struct disk_io_req
{
	static constexpr size_t sector_mask = ~((size_t) 4095);

	bool active = false;

	size_t offset{};
	size_t length{};

	size_t io_offset = 0;
	size_t io_length = 0;

	/* Offset relativ to 4096 bytes */
	size_t req_offset = 0;


	/* Spare 4096 bytes at the beginning for a full-sector read, and another
	 * 4096 bytes on top of that for the message header. */
	fixed_aligned_buffer buf{4096, MAX_IO_REQ_SIZE + 4096*2};

	struct iovec iov{};

	inline void update_io_params()
	{
		/* Round down to sector size. The extra up-to 4095 bytes will fit into
		 * the spare of the buffer at the beginning. */
		io_offset = offset & sector_mask;

		/* Round length up to the sector size. Note that the total length will
		 * never be more than one additional sector. */
		io_length = ((offset - io_offset) + length + 4095) & sector_mask;

		if (io_length > MAX_IO_REQ_SIZE + 4096)
			throw std::runtime_error("IO buffer too small");

		iov.iov_base = buf.ptr() + 4096 + req_offset;
		iov.iov_len = io_length - req_offset;
	}

	std::shared_ptr<dd_client> client;
	uint64_t client_request_id{};
	char* base_for_send = nullptr;
	size_t length_for_send = 0;

	/* Data from client write request */
	dynamic_aligned_buffer wr_buf;
	const char* wr_base = nullptr;
};


class dd_ctx final
{
public:
	static constexpr unsigned max_ios_in_flight = 256;

protected:
	WrappedFD wfd;
	DeviceInfo di;

	Epoll epoll;
	SignalFD sfd{
		{SIGINT, SIGTERM},
		epoll,
		std::bind(&dd_ctx::on_signal, this, std::placeholders::_1)};

	/* NOTE: Epoll comes before because IOUring polls epoll's filedescriptor */
	/* poll + in-flight */
	IOUring io_uring{next_power_of_two(max_ios_in_flight + 2)};

	int port = 0;
	WrappedFD sock;

	WrappedFD mgr_sock;

	bool quit_requested = false;


	/* Disk IO */
	/* Queue (actually not really a queue because entries might complete out of
	 * order and be reassigned) */
	std::array<disk_io_req, max_ios_in_flight> io_queue;


	/* Clients */
	std::vector<std::shared_ptr<dd_client>> clients;

	/* Be careful when calling these functions */
	void remove_client(decltype(clients)::iterator i);
	void remove_client(std::shared_ptr<dd_client> client);

	void initialize_sock();
	void initialize_mgr();

	void on_signal(int s);
	void on_listen_sock(int fd, uint32_t events);

	/* Buffer pool for requests */
	dynamic_aligned_buffer_pool buf_pool_client{4096, 8};

	void on_client_fd(std::shared_ptr<dd_client> client, int fd, uint32_t events);

	bool process_client_message(std::shared_ptr<dd_client> client, dynamic_aligned_buffer&& buf, size_t msg_len);
	bool process_client_message(std::shared_ptr<dd_client> client, const prot::dd::req::getattr& msg);
	bool process_client_message(std::shared_ptr<dd_client> client, const prot::dd::req::read& msg);
	bool process_client_message(std::shared_ptr<dd_client> client, const prot::dd::req::write& msg,
			dynamic_aligned_buffer&& buf);

	bool send_message_to_client(std::shared_ptr<dd_client> client, const prot::msg& msg);
	bool send_message_to_client(std::shared_ptr<dd_client> client,
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len);

	bool send_message_to_client(disk_io_req* qe);

	/* Disk IO */
	disk_io_req* get_free_io_queue_entry();

public:
	static void return_io_queue_entry(disk_io_req* qe);

protected:

	/* io uring event handlers */
	void on_epoll_ready(int res);
	void on_read_io_finished(disk_io_req* qe, int res);
	void on_write_read_finished(disk_io_req* qe, int res);
	void on_write_io_finished(disk_io_req* qe, int res);

	void write_req_write(disk_io_req* qe);

	/* Error logging */
	void log_io_error(disk_io_req*, int code);

public:
	const std::string device_file;

	dd_ctx(const std::string& device_file);
	~dd_ctx();

	void initialize();
	void main();
};

#endif /* __DD_CTX_H */
