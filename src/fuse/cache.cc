#include <array>
#include "cache.h"

using namespace std;


Cache::request_t::request_t(unsigned long node_id, size_t offset, size_t size)
	: node_id(node_id), offset(offset), size(size)
{
}

Cache::cache_entry_t::cache_entry_t(const prot::client::reply::read& msg,
		buffer_pool_returner&& bp_ret, unsigned long access_time)
	: msg(msg), bp_ret(move(bp_ret)), access_time(access_time)
{
}


Cache::Cache(com_ctx& cctx)
	: cctx(cctx)
{
}

Cache::~Cache()
{
}


void Cache::cb_read(shared_ptr<request_t> req, prot::client::reply::read& msg,
		dynamic_aligned_buffer_pool& bp, dynamic_aligned_buffer&& buf)
{
	buffer_pool_returner bp_ret(bp, move(buf));

	unique_lock lk(m);

	/* Find request */
	auto ireq = requests.find({req->node_id, req->offset, req->size});
	if (ireq == requests.end() || ireq->second != req)
		throw runtime_error("tried to finish non-existing read request");

	requests.erase(ireq);


	if (msg.size <= max_size)
	{
		/* Expire cache entries */
		while (cache_size + msg.size > max_size && cache.size() > 0)
		{
			auto i_min = cache.begin();
			auto t_min = i_min->second.access_time;

			for (auto i = cache.begin(); i != cache.end(); i++)
			{
				if (i->second.access_time < t_min)
				{
					i_min = i;
					t_min = i->second.access_time;
				}
			}

			cache_size -= i_min->second.msg.size;
			cache.erase(i_min);
		}

		/* Add to cache */
		cache_size += msg.size;
		cache.try_emplace(
				tuple(req->node_id, req->offset, req->size),
				msg, move(bp_ret),
				++access_cnt);

		//printf("cache_size: %d\n", (int) cache_size);
	}

	/* Call cbs */
	for (auto& cb : req->cbs)
		cb(msg.res, msg.size, msg.data);
}


void Cache::read(unsigned long node_id, size_t offset, size_t size,
		cb_read_t cb)
{
	unique_lock lk(m);
	bool need_region = true;

	/* Check if region is in cache */
	auto icache = cache.find({node_id, offset, size});
	if (icache != cache.end())
	{
		//printf("cache hit\n");

		auto& msg = icache->second.msg;
		//icache->second.access_time = ++access_cnt;
		cb(msg.res, msg.size, msg.data);
		need_region = false;
	}


	/* If not, fetch region */
	/* Check if region is currently fetched */
	if (need_region)
	{
		auto i = requests.find({node_id, offset, size});
		if (i != requests.end())
		{
			i->second->cbs.push_back(cb);
			need_region = false;
		}
	}

	if (need_region)
		cnt_misses++;
	else
		cnt_hits++;

	{
		auto t_now = get_monotonic_time();
		if (t_now - last_report_time > 1000000000ULL)
		{
			printf("cache efficiency (including RA): %5.1f%% hits\n",
					(double) cnt_hits / (cnt_hits + cnt_misses) * 100.);

			cnt_hits = cnt_misses = 0;

			last_report_time = t_now;
		}
	}

	/* Fetch region if required */
	size_t cnt_reqs = 0;
	array<shared_ptr<request_t>, 64> reqs;

	if (need_region)
	{
		reqs[0] = make_shared<request_t>(node_id, offset, size);
		reqs[0]->cbs.push_back(cb);
		requests.insert({{node_id, offset, size}, reqs[0]});

		cnt_reqs++;
	}

	/* Read-ahead */
	if (ra_enabled && size >= (128 * 1024) && size < (2 * 1024 * 1024) &&
			offset % size == 0 && size % (128 * 1024) == 0)
	{
		size_t j = cnt_reqs;
		for (size_t i = cnt_reqs; i < reqs.size(); i++)
		{
			auto ra_offset = offset + size*i;

			if (requests.find({node_id, ra_offset, size}) != requests.end())
				continue;

			if (cache.find({node_id, ra_offset, size}) != cache.end())
				continue;

			//printf("  ra: %lu %zu %zu\n", node_id, ra_offset, size);

			reqs[j] = make_shared<request_t>(node_id, ra_offset, size);
			requests.insert({{node_id, ra_offset, size}, reqs[j]});

			cnt_reqs++;
			j++;
		}
	}

	lk.unlock();

	for (size_t i = 0; i < cnt_reqs; i++)
	{
		auto& req = reqs[i];
		cctx.request_read(
				req->node_id,
				req->offset,
				req->size,
				bind_front(&Cache::cb_read, this, req));
	}
}





//	check_call(fuse_reply_buf(req, msg.data, msg.size), "fuse_reply_data");
