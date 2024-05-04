#ifndef __PROFILER_H
#define __PROFILER_H

#include <string>


/* Public interface */
class Profiler;

class ProfilerProxy
{
protected:
	Profiler& p;

public:
	ProfilerProxy(Profiler& p);
	~ProfilerProxy();

	void start();
	void stop();
};

/* The return value must only be used by one thread at a time. If another thread
 * needs concurrent access, retrieve another ProfilerProxy with profiler_get. */
ProfilerProxy profiler_get(const std::string& name);

void profiler_list();
void profiler_list(unsigned long long div);

#endif /* __PROFILER_H */
