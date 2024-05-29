#ifndef __CACHE_H
#define __CACHE_H

#include <functional>
#include <mutex>
#include <memory>
#include <map>
#include <tuple>
#include "com_ctx.h"


class Cache
{
public:
	using cb_read_t = std::function<void(int res, size_t size, const char* data)>;

protected:
	struct request_t final
	{
		unsigned long node_id;
		size_t offset;
		size_t size;

		std::vector<cb_read_t> cbs;

		request_t(unsigned long node_id, size_t offset, size_t size);
	};

	struct cache_entry_t final
	{
		prot::client::reply::read msg;
		buffer_pool_returner bp_ret;

		unsigned long access_time;

		cache_entry_t(
				const prot::client::reply::read& msg,
				buffer_pool_returner&& bp_ret,
				unsigned long access_time);
	};


	std::mutex m;
	com_ctx& cctx;

	std::map<std::tuple<unsigned long, size_t, size_t>, std::shared_ptr<request_t>> requests;

	size_t cache_size = 0;
	const size_t max_size = 128 * 1024 * 1024UL;

	size_t cnt_hits = 0;
	size_t cnt_misses = 0;
	unsigned long long last_report_time = 0;

	std::map<
		std::tuple<unsigned long, size_t, size_t>,
		cache_entry_t> cache;

	unsigned long access_cnt = 0;

	const bool ra_enabled = true;


	void cb_read(std::shared_ptr<request_t> req, prot::client::reply::read& msg,
			dynamic_aligned_buffer_pool& bp, dynamic_aligned_buffer&& buf);

public:
	Cache(com_ctx& cctx);
	virtual ~Cache();

	void read(unsigned long node_id, size_t offset, size_t size, cb_read_t cb);
};

#endif /* __CACHE_H */
