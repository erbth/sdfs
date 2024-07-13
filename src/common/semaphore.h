#ifndef __COMMON_SEMAPHORE_H
#define __COMMON_SEMAPHORE_H

#include <mutex>
#include <condition_variable>

class semaphore
{
private:
	std::mutex m;
	unsigned int counter;

	std::condition_variable c;

public:
	semaphore(unsigned int init);

	void up();
	void down();

	/* Waits at most for the specified timeout (might return earlier even if the
	 * down-operation was not successful); Returns true if down operation was
	 * successful, false if it timed out */
	template<class Rep, class Period>
	bool try_down(const std::chrono::duration<Rep, Period>& timeout)
	{
		std::unique_lock lk(m);
		if (counter == 0)
			c.wait_for(lk, timeout);

		if (counter == 0)
			return false;

		counter--;
		return true;
	}

	/* Like try_down above, but returns immediately */
	inline bool try_down()
	{
		std::unique_lock lk(m);
		if (counter == 0)
			return false;

		counter--;
		return true;
	}
};

#endif /* __COMMON_SEMAPHORE_H */
