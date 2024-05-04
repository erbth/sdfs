#include <ctime>
#include <map>
#include <mutex>
#include <algorithm>
#include <vector>
#include <utility>
#include <system_error>
#include "common/profiler.h"

using namespace std;


static_assert(sizeof(unsigned long long) >= 8);
static_assert(sizeof(long long) >= 8);


class Profiler
{
protected:
	mutable mutex m;

	const string name;

	bool running = false;
	struct timespec t_start{};

	unsigned long long total_duration = 0;

public:
	Profiler(const string& name)
		: name(name)
	{
	}

	void start()
	{
		unique_lock lk(m);

		if (!running)
		{
			if (clock_gettime(CLOCK_MONOTONIC, &t_start) < 0)
				throw system_error(errno, generic_category(), "clock_gettime");

			running = true;
		}
	}

	void stop()
	{
		unique_lock lk(m);

		if (running)
		{
			struct timespec t_stop;
			if (clock_gettime(CLOCK_MONOTONIC, &t_stop) < 0)
				throw system_error(errno, generic_category(), "clock_gettime");

			long long duration =
				(t_stop.tv_sec - t_start.tv_sec) * 1000000000LL +
				(t_stop.tv_nsec - t_start.tv_nsec);

			total_duration += duration;

			running = false;
		}
	}

	unsigned long long get_total_duration() const
	{
		unique_lock lk(m);
		return total_duration;
	}
};

ProfilerProxy::ProfilerProxy(Profiler& p)
	: p(p)
{
}

ProfilerProxy::~ProfilerProxy()
{
	p.stop();
}

void ProfilerProxy::start()
{
	p.start();
}

void ProfilerProxy::stop()
{
	p.stop();
}


class ProfilerRegistry
{
protected:
	mutex m;

	map<string, Profiler> profilers;
	struct timespec t_last_list{};

public:
	Profiler& get(const string& name)
	{
		unique_lock lk(m);

		auto i = profilers.find(name);
		if (i == profilers.end())
		{
			auto [i_new, inserted] = profilers.emplace(name, name);
			i = i_new;
		}

		return i->second;
	}

	void list(unsigned long long div)
	{
		unique_lock lk(m);

		struct timespec t_now;
		if (clock_gettime(CLOCK_MONOTONIC, &t_now) < 0)
			throw system_error(errno, generic_category(), "clock_gettime");

		vector<pair<decltype(profilers)::const_iterator, unsigned long long>> index;

		size_t max_length = 0;
		for (auto i = profilers.cbegin(); i != profilers.cend(); i++)
		{
			max_length = max(max_length, i->first.size());
			index.emplace_back(i, i->second.get_total_duration());
		}

		sort(index.begin(), index.end(), [](auto a, auto b) { return a.second > b.second; });

		unsigned long long total_d = 0;

		fprintf(stderr, "\n\033[96mProfilers:\n");
		for (const auto& [i, d] : index)
		{
			total_d += d;

			fprintf(stderr, "    %-*s  %.6fms\n",
					(int) (max_length + 1), (i->first + ":").c_str(),
					(d / 1e6) / div);
		}

		unsigned long long last_list_diff =
			(t_now.tv_sec - t_last_list.tv_sec) * 1000000000LL + 
			(t_now.tv_nsec - t_last_list.tv_nsec);

		t_last_list = t_now;

		fprintf(stderr, "  total:  %.6fms\n  time since last report:  %.6fms\033[0m\n",
				(total_d / 1e6) / div,
				(last_list_diff / 1e6));
	}
};


ProfilerRegistry reg{};


ProfilerProxy profiler_get(const string& name)
{
	auto& p = reg.get(name);
	ProfilerProxy pp(p);
	p.start();

	return pp;
}

void profiler_list()
{
	profiler_list(1);
}

void profiler_list(unsigned long long div)
{
	reg.list(div);
}
