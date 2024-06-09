#ifndef __CTRL_CTX_H
#define __CTRL_CTX_H

#include <list>
#include <map>
#include <set>
#include <optional>
#include <queue>
#include <deque>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <variant>
#include <functional>
#include "common/fixed_buffer.h"
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"
#include "common/prot_dd.h"
#include "common/open_list.h"
#include "common/io_uring.h"
#include "common/timerfd.h"

extern "C" {
#include <netinet/in.h>
#include <sys/uio.h>
}


#define SEND_STATIC_BUF_SIZE 128

static_assert(sizeof(unsigned long) >= 8);
static_assert(sizeof(long) >= 8);
static_assert(sizeof(unsigned) >= 4);


/* Prototypes */
class ctrl_dd;
class client_path_t;


using cb_send_on_path_finished_t = std::function<void()>;


struct io_request_t
{
	io_request_t& operator=(io_request_t&&) = delete;

	client_path_t* path{};
	unsigned long seq{};

	/* A buffer for the message header etc. */
	size_t static_buf_size = 0;
	char static_buf[SEND_STATIC_BUF_SIZE];

	/* Receiving the request */
	char* rcv_ptr = nullptr;
	size_t rcv_rem_size = 0;

	/* IO parameters */
	size_t offset{};
	size_t count{};

	/* Buffer */
	fixed_buffer buf;
};

struct send_queue_element_t
{
	send_queue_element_t& operator=(send_queue_element_t&&) = delete;

	char static_buf[SEND_STATIC_BUF_SIZE];

	int iov_cnt = 0;
	struct iovec iov[8]{};

	cb_send_on_path_finished_t cb_finished;
};


/* Client interface */
struct client_request_t
{
	/* Receiving the request */
	char* rcv_ptr = nullptr;
	size_t rcv_rem_size = 0;

	/* Responding to the request */

	/* Buffers */
};

struct client_t
{
	client_t& operator=(client_t&&) = delete;

	unsigned client_id = 0;

	std::vector<client_path_t*> paths;
};

struct client_path_t
{
	client_path_t& operator=(client_path_t&&) = delete;

	struct sockaddr_in6 remote_addr{};
	client_t* client = nullptr;

	WrappedFD wfd;

	uint64_t requires_probe = 0;
	uint64_t wait_for_probe = 0;

	/* Sending data */
	bool sender_enabled = false;
	std::queue<send_queue_element_t> send_queue;

	/* Receiving data */
	char rcv_buf[1024];
	size_t rcv_buf_size = 0;

	client_request_t* rcv_req = nullptr;
};


/* Data map */
struct data_map_t
{
	const size_t block_size = 1024 * 1024;
	size_t size{};
	size_t cnt_blocks{};

	std::vector<ctrl_dd*> dd_order;
};


/* Contexts for dd IO */
struct dd_read_request_t
{
	using cb_completed_t = std::function<void(dd_read_request_t&&)>;

	ctrl_dd* dd;
	size_t offset;
	size_t size;
	cb_completed_t cb_completed;

	/* Will be filled by dd_read */
	int result = -1;
	const char* data = nullptr;

	/* The data is stored somewhere in this buffer */
	dynamic_aligned_buffer _buf;
};

struct dd_write_request_t
{
	using cb_completed_t = std::function<void(dd_write_request_t&&)>;

	ctrl_dd* dd;
	size_t offset;
	size_t size;
	const char* data = nullptr;
	cb_completed_t cb_completed;

	/* Will be filled by dd_write */
	int result = -1;
};


struct ctrl_dd final
{
	WrappedFD wfd;

	unsigned id;
	char gid[16];
	int port;

	size_t size;

	/* Only true after the DD's connection has been fully initialized */
	bool connected = false;


	/* Receiving messages from the dd */
	dynamic_aligned_buffer rd_buf;
	size_t rd_buf_pos = 0;

	/* Sending messages to the dd */
	//std::queue<ctrl_queued_msg> send_queue;
	size_t send_msg_pos = 0;

	/* Outstanding requests */
	std::map<uint64_t, dd_read_request_t> read_reqs;
	std::map<uint64_t, dd_write_request_t> write_reqs;


	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


class ctrl_ctx final
{
protected:
	FileConfig cfg;

	bool quit_requested = false;
	bool quit_main_loop = false;

	Epoll ep;
	SignalFD sfd{
		{SIGINT, SIGTERM},
		ep,
		std::bind_front(&ctrl_ctx::on_signal, this)};


	/* dds */
	std::list<ctrl_dd> dds;

	/* clients */
	WrappedFD client_lfd;

	uint32_t next_client_id = 1;

	std::list<client_t> clients;
	std::list<client_path_t> client_paths;
	std::list<client_path_t> new_client_paths;
	std::list<client_path_t> client_paths_to_remove;

	void cleanup_clients();

	bool parse_client_message_simple(client_path_t* p, const char* buf, size_t size, uint32_t msg_num);
	bool parse_client_message_connect(client_path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_client_message_resp_probe(client_path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_client_message_getattr(client_path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_client_message_read(client_path_t* p, const char* buf, size_t size, uint64_t seq);

	void send_io_req_read_finished(std::list<io_request_t>::iterator i);

	void send_on_client_path_static(
			client_path_t* p,
			const char* static_buf, size_t static_size,
			const char* user_ptr = nullptr, size_t user_size = 0,
			cb_send_on_path_finished_t cb_finished = nullptr);

	uint64_t next_probe_token = 1;
	std::set<uint64_t> active_probe_tokens;
	uint64_t get_probe_token();
	void free_probe_token(uint64_t token);


	/* Request id generator */
	uint64_t next_request_id = 0;
	uint64_t get_request_id();

	/* Buffer pools for requests and dd IO (two different pools because the
	 * request classes can differ in size) */
	dynamic_aligned_buffer_pool buf_pool_req{4096, 8};
	dynamic_aligned_buffer_pool buf_pool_dd_io{4096, 64};


	/* Data map */
	data_map_t data_map;

	std::list<io_request_t> io_requests;


	/* dd IO interface */
	void dd_read(dd_read_request_t&& req);
	void dd_write(dd_write_request_t&& req);


	void print_cfg();

	std::pair<WrappedFD, struct sockaddr_in6> initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_data_map();
	void initialize_client_listener();

	void on_signal(int s);

	void on_client_lfd(int fd, uint32_t events);
	void on_client_path_fd(client_path_t* path, int fd, uint32_t events);

	void on_dd_fd(ctrl_dd* dd, int fd, uint32_t events);


	bool process_dd_message(ctrl_dd& dd, dynamic_aligned_buffer&& buf, size_t msg_len);
	bool process_dd_message(ctrl_dd& dd, prot::dd::reply::read& msg, dynamic_aligned_buffer&& buf);
	bool process_dd_message(ctrl_dd& dd, prot::dd::reply::write& msg);

	bool send_message_to_dd(ctrl_dd& dd, const prot::msg& msg,
			const char* data = nullptr, size_t data_length = 0);

	bool send_message_to_dd(ctrl_dd& dd,
			std::variant<dynamic_buffer, dynamic_aligned_buffer>&& buf, size_t msg_len);


public:
	ctrl_ctx();
	~ctrl_ctx();

	void initialize();
	void main();
};

#endif /* __CTRL_CTX_H */
