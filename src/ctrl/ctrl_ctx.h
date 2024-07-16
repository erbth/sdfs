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
#include <deque>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "common/fixed_buffer.h"
#include "common/utils.h"
#include "common/epoll.h"
#include "common/signalfd.h"
#include "common/file_config.h"
#include "common/dynamic_buffer.h"
#include "common/prot_client.h"
#include "common/prot_dd.h"
#include "common/open_list.h"
#include "common/timerfd.h"
#include "common/semaphore.h"
#include "common/eventfd.h"

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
class send_thread_t;
class ctrl_ctx;


using cb_send_on_path_finished_t = std::function<void()>;


struct dd_request_t
{
	using cb_completed_t = void(*)(void*);

	ctrl_dd* dd{};
	size_t offset{};
	size_t size{};
	char* data{};
	bool dir_write = false;

	cb_completed_t cb_completed{};
	void* cb_arg{};

	/* Will be filled by dd_req */
	int result = -1;
};


struct io_request_t
{
	io_request_t& operator=(io_request_t&&) = delete;

	ctrl_ctx* ctrl_ptr{};      // For use by IO callbacks
	client_path_t* path{};
	unsigned long seq{};

	/* A buffer for the message header etc. */
	//size_t static_buf_size = 0;
	char static_buf[SEND_STATIC_BUF_SIZE];

	/* Receiving the request */
	char* rcv_ptr = nullptr;
	size_t rcv_rem_size = 0;

	/* IO parameters */
	size_t offset{};
	size_t count{};

	/* 32 chunks + one extra chunk if IO is not aligned */
	std::array<dd_request_t, 33> dd_reqs;
	size_t cnt_dd_reqs;
	std::atomic<size_t> cnt_completed_dd_reqs;

	/* Buffer */
	fixed_buffer buf;
};


/* Client interface */
struct client_t
{
	client_t& operator=(client_t&&) = delete;

	unsigned client_id = 0;

	std::vector<client_path_t*> paths;
};


struct send_queue_element_t final
{
	send_queue_element_t() = default;
	send_queue_element_t(send_queue_element_t&) = delete;
	send_queue_element_t& operator=(send_queue_element_t&) = delete;

	inline send_queue_element_t(send_queue_element_t&& o)
		:
			iov_cnt(o.iov_cnt), iov(o.iov), cb_finished(o.cb_finished),
			buf(o.buf), iio_req(move(o.iio_req))
	{
		o.buf = nullptr;
	}

	inline ~send_queue_element_t()
	{
		if (buf)
			free(buf);
	}


	int iov_cnt = 0;
	struct iovec iov[8]{};

	cb_send_on_path_finished_t cb_finished;
	char* buf = nullptr;

	std::optional<std::list<io_request_t>::iterator> iio_req;
};

struct client_path_t
{
	client_path_t& operator=(client_path_t&&) = delete;

	struct sockaddr_in6 remote_addr{};
	client_t* client = nullptr;

	/* MUST NOT be changed after initialization */
	WrappedFD wfd;
	send_thread_t* send_thread = nullptr;

	uint64_t requires_probe = 0;
	uint64_t wait_for_probe = 0;

	/* Receiving data */
	char rcv_buf[1024];
	size_t rcv_buf_size = 0;

	/* Sending data */
	bool sender_enabled = false;
	std::queue<send_queue_element_t> send_queue;


	io_request_t* req = nullptr;
	std::list<io_request_t>::iterator i_req;
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
struct dd_send_queue_element_t final
{
	int iov_cnt = 0;
	struct iovec iov[2]{};

	char static_buf[32];
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
	char rcv_buf[1024];
	size_t rcv_buf_size = 0;

	char* rcv_ext_ptr = nullptr;
	size_t rcv_ext_cnt = 0;


	/* Sending messages to the dd */
	std::queue<dd_send_queue_element_t> send_queue;
	size_t send_msg_pos = 0;


	/* Outstanding requests */
	std::mutex m_active_reqs;
	std::map<uint64_t, dd_request_t*> active_reqs;


	decltype(active_reqs)::iterator rcv_req;


	inline int get_fd()
	{
		return wfd.get_fd();
	}
};


struct thread_msg_t final
{
	enum : unsigned {
		TYPE_QUIT = 1,
		TYPE_ADD_CLIENT_PATH,
		TYPE_REMOVE_CLIENT_PATH,
		TYPE_SEND
	};
	unsigned type;

	inline thread_msg_t(unsigned type)
		: type(type)
	{
	}


	client_path_t* client_path = nullptr;
	send_queue_element_t sqe;


	/* Some messages can be acknowledged as processed */
	std::shared_ptr<sync_point> sp;

	inline void acknowledge()
	{
		if (sp)
			sp->flag();
	}
};


class worker_thread_base_t
{
protected:
	Epoll ep;
	EventFD efd{ep, std::bind(&worker_thread_base_t::on_efd, this)};


	/* Message box for IPC */
	semaphore mb_sema_free{128 * 1024};
	semaphore mb_sema_avail{0};
	std::mutex m_mb_queue;
	std::deque<thread_msg_t> mb_queue;

	void on_efd();

public:
	virtual ~worker_thread_base_t() = 0;

	/* Functions below this comment may be called from different threads */
	void msg(thread_msg_t&& msg);
};


class recv_thread_t final : public worker_thread_base_t
{
protected:
	ctrl_ctx& cctx;
	std::vector<ctrl_dd*> dds;

	bool running{true};

	void process_inbox();

	void on_dd_fd_read(ctrl_dd* dd, int fd, uint32_t events);

public:
	recv_thread_t(ctrl_ctx& cctx, std::vector<ctrl_dd*>&& dds);
	~recv_thread_t();

	void main();
};


class send_thread_t final : public worker_thread_base_t
{
protected:
	ctrl_ctx& cctx;

	bool running{true};

	void process_inbox();

	/* Client paths */
	std::vector<client_path_t*> client_paths;

	/* Receivers of IPC calls */
	void _add_client_path(client_path_t*);


	/* Maintaining client paths */
	void _remove_client_path(client_path_t*);


	/* Send handlers */
	void on_client_fd(client_path_t* path, int fd, uint32_t events);

public:
	send_thread_t(ctrl_ctx& cctx);

	/* IMPORTANT NOTE: Not all of the public functions can be used directly by
	 * other threads; some may only be used during initialization. See comments
	 * below. */
	std::vector<ctrl_dd*> dds;

	void main();

	/* Functions below this comment may be called from different threads */
	std::list<client_path_t*> get_client_paths();
	void add_client_path(client_path_t*);
};


class ctrl_ctx final
{
	friend recv_thread_t;
	friend send_thread_t;

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
	bool parse_client_message_write(client_path_t* p, const char* ptr, size_t size, size_t data_len);

	void complete_parse_client_write_request(client_path_t*);

	/* Callbacks for client message processing */
	static void _dd_io_complete_client_read(void*);
	void dd_io_complete_client_read(std::list<io_request_t>::iterator);

	static void _dd_io_complete_client_write(void* arg);
	void dd_io_complete_client_write(std::list<io_request_t>::iterator io_req);

	/* Slow */
	void send_on_client_path_static(
			client_path_t* p, const char* static_buf, size_t static_size);

	void send_on_client_path_req(
			std::list<io_request_t>::iterator iio_req,
			char* ptr1, size_t size1,
			char* ptr2 = nullptr, size_t size2 = 0);


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

	size_t split_io(size_t offset, size_t size,
			dd_request_t* reqs, size_t max_req_count);

	/* IO requests */
	/* Must only be used by functions below */
	std::mutex m_io_requests;
	std::list<io_request_t> io_requests;

	decltype(io_requests)::iterator add_io_request();
	void remove_io_request(decltype(io_requests)::iterator);


	/* dd IO interface */
	void dd_req(dd_request_t* req);


	/* Worker threads */
	std::list<recv_thread_t> recv_threads;
	std::vector<std::thread> recv_thread_tobjs;

	std::list<send_thread_t> send_threads;
	std::vector<std::thread> send_thread_tobjs;


	void print_cfg();

	std::pair<WrappedFD, struct sockaddr_in6> initialize_dd_host(const std::string& addr_str);
	void initialize_connect_dd(const struct in6_addr& addr, ctrl_dd& dd);

	void initialize_cfg();
	void initialize_connect_dds();
	void initialize_data_map();
	void initialize_client_listener();
	void initialize_start_recv_threads();
	void initialize_start_send_threads();

	void on_signal(int s);

	void on_client_lfd(int fd, uint32_t events);
	void on_client_path_fd(client_path_t* path, int fd, uint32_t events);

	void on_dd_fd(ctrl_dd* dd, int fd, uint32_t events);


	bool parse_dd_message_simple(ctrl_dd* dd, const char* buf, size_t size, uint32_t msg_num);
	bool parse_dd_message_read(ctrl_dd* dd, const char* ptr, size_t size, size_t data_len);
	bool parse_dd_message_write(ctrl_dd* dd, const char* ptr, size_t size);

	void complete_dd_read_request(ctrl_dd* dd);

	void send_to_dd(ctrl_dd* dd, const char* static_buf, size_t static_size,
			const char* data = nullptr, size_t data_size = 0);


public:
	ctrl_ctx();
	~ctrl_ctx();

	void initialize();
	void main();
};

#endif /* __CTRL_CTX_H */
