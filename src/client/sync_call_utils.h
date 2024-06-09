#ifndef __CLIENT_SYNC_CALL_UTILS_H
#define __CLIENT_SYNC_CALL_UTILS_H

#include <mutex>
#include <condition_variable>

class Synchronizer final
{
protected:
	bool finished = false;
	int status;

	std::mutex m;
	std::condition_variable c;

	void _cb_finished(size_t handle, int status)
	{
		{
			std::unique_lock lk(m);
			this->status = status;
			finished = true;
		}

		c.notify_one();
	}

public:
	static void cb_finished(size_t handle, int status, void* arg)
	{
		reinterpret_cast<Synchronizer*>(arg)->_cb_finished(handle, status);
	}

	int wait()
	{
		std::unique_lock lk(m);
		while (!finished)
			c.wait(lk);

		return status;
	}
};

#endif /* __CLIENT_SYNC_CALL_UTILS_H */
