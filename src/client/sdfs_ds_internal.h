/* The public interface provides a wrapper object; this header defines the
 * 'real' implementation. */
#ifndef __CLIENT_SDFS_DS_INTERNAL_H
#define __CLIENT_SDFS_DS_INTERNAL_H

#include <string>
#include <vector>
#include <list>
#include <thread>
#include <functional>
#include <atomic>
#include <queue>
#include <utility>
#include "common/utils.h"
#include "common/epoll.h"
#include "common/eventfd.h"
#include "common/fixed_buffer.h"
#include "sdfs_ds.h"

extern "C" {
#include <netinet/in.h>
#include <sys/uio.h>
}


#define SEND_STATIC_BUF_SIZE 128

static_assert(sizeof(unsigned) >= 4);

/* Prototypes */
class DSClient;


struct io_request_t
{
	io_request_t& operator=(io_request_t&&) = delete;

	unsigned long seq{};

	size_t offset{};

	/* A buffer for the message header etc. */
	size_t static_buf_size = 0;
	char static_buf[SEND_STATIC_BUF_SIZE];

	/* User pointers */
	sdfs::cb_async_finished_t cb_finished = nullptr;
	void* user_arg = nullptr;
	size_t data_size = 0;
	char* data_ptr = nullptr;

	/* TODO: Account send data to io_request; i.e. if io_request is aborted or
	 * 'finished' by a wrong reply from the server while the data is still sent
	 * */
	bool send_data = false;
};

struct send_queue_element_t
{
	send_queue_element_t& operator=(send_queue_element_t&&) = delete;

	char static_buf[SEND_STATIC_BUF_SIZE];

	int iov_cnt = 0;
	struct iovec iov[8]{};
};

struct path_t final
{
	unsigned path_id = 0;
	EventFD* thread_efd = nullptr;

	std::string srv_desc;
	struct sockaddr_in6 addr{};

	/* !bool(wfd)              unconnected
	 * bool(wfd) && !accepted  validating
	 * accepted    connected */
	WrappedFD wfd;
	bool accepted = false;

	/* Sending data */
	bool sender_enabled = false;
	std::queue<send_queue_element_t> send_queue;

	/* Receiving data */
	char rcv_buf[1024];
	size_t rcv_buf_size = 0;

	std::map<unsigned long, std::unique_ptr<io_request_t>> io_requests;

	decltype(io_requests)::iterator rcv_req;
	char* rcv_req_ptr = nullptr;
	size_t rcv_req_size = 0;

	/* A mutex for the state- and send parts. It protects:
	 *   * wfd (but it may only be closed by the worker thread)
	 *   * accepted (but it may only be modified by the worker thread)
	 *   * sender_enabled
	 *   * io_requests (but only the worker thread may delete entries)
	 *   * send_queue (but only the worker thread may delete entries) */
	std::mutex m_state_send;
};

struct worker_thread_ctx final
{
	DSClient* ds_client = nullptr;

	const unsigned thread_id{};

	/* This is a remote state variable */
	std::atomic<bool>* wt_quit = nullptr;

	bool stop_thread = false;

	void on_eventfd();

	Epoll ep;
	EventFD efd{ep, std::bind(&worker_thread_ctx::on_eventfd, this)};

	std::atomic<bool>* next_connect_paths = nullptr;
	EventFD* next_efd = nullptr;

	std::atomic<bool> connect_paths = false;

	/* Called from the main thread, as is the destructor */
	inline worker_thread_ctx(const unsigned thread_id, std::atomic<bool>* wt_quit)
		: thread_id(thread_id), wt_quit(wt_quit)
	{
	}

	worker_thread_ctx(worker_thread_ctx&&) = delete;

	/* Paths to be used and managed by this thread */
	std::vector<path_t*> paths;
	void on_path_fd(path_t* path, int fd, uint32_t events);

	std::atomic<uint32_t>* client_id = nullptr;
	std::atomic<unsigned long>* next_seq = nullptr;

	bool path_status_changed = false;

	uint64_t completed_probe_round{};


	std::unique_ptr<io_request_t> remove_io_request(path_t* p, uint64_t seq);


	void send_on_path_static(path_t* p, const char* buf, size_t size);


	bool parse_message_simple(path_t* p, const char* buf, size_t size, uint32_t msg_num);
	bool parse_message_accept(path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_message_req_probe(path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_message_getattr(path_t* p, const char* buf, size_t size, uint64_t seq);
	bool parse_message_read(path_t* p, const char* buf, size_t buf_size, size_t size);
	bool parse_message_write(path_t* p, const char* buf, size_t size, uint64_t seq);
	bool finish_message_read(path_t* p);


	void main();
};


class DSClient final
{
	friend worker_thread_ctx;

protected:
	/* Guards everything not guarded by a separate mutex.
	 * Do not use any of the guarded fields in threads (atomics do not fulfill
	 * under this condition). */
	std::mutex m;

	std::list<path_t> paths;
	std::vector<path_t*> path_order;

	/* State-utility functions */
	void init_paths(const std::vector<std::string>& srv_portals);
	void init_start_threads();  // Must be called last during initialization

	void cleanup(std::unique_lock<std::mutex>&);

	/* Worker threads */
	std::atomic<bool> wt_quit{false};
	std::vector<std::thread> worker_threads;

	/* Do not touch corresp. entry while specific thread is running */
	std::list<worker_thread_ctx> per_thread_ctx;

	std::vector<EventFD*> wt_efds;
	void wt_signal_all();
	void wt_signal_all_except(unsigned thread_id);

	std::atomic<uint32_t> client_id{0};
	std::atomic<unsigned long> next_seq{0};

	uint64_t probe_token{};
	uint64_t probe_seq{};
	std::atomic<uint64_t> probe_round{};

	/* Returns nullptr if no path is available; the returned lock is for
	 * path_t::m_state_send */
	std::pair<path_t*, std::unique_lock<std::mutex>> choose_path(unsigned long seq);


	/* IO request queue */
	std::queue<std::unique_ptr<io_request_t>> io_req_queue;

	/* Tries to schedule the given io_req; only moves from it when scheduling
	 * was successful, i.e. if it returns true */
	bool schedule_io_request(std::unique_ptr<io_request_t>&& io_req);

	void submit_io_request(std::unique_ptr<io_request_t>&& io_req);


public:
	DSClient(const std::vector<std::string>& srv_portals);
	~DSClient();

	/* Public s.t. these functions can be used by worker threads; however take
	 * care of correct locking */
	void print_path_status();
	void schedule_pending_io_requests();

	/* Return a handle */
	size_t getattr(sdfs::ds_attr_t* dst,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	/* Read either the entire block or nothing */
	size_t read(void* buf, size_t offset, size_t count,
			sdfs::cb_async_finished_t cb_finished, void* arg);

	/* Write either the entire block or nothing */
	size_t write(const void* buf, size_t offset, size_t count,
			sdfs::cb_async_finished_t cb_finished, void* arg);
};

#endif /* __CLIENT_SDFS_DS_INTERNAL_H */
