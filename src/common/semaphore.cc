#include "semaphore.h"

using namespace std;

semaphore::semaphore(unsigned int init)
	: counter(init)
{
}

void semaphore::up()
{
	unique_lock lk(m);
	counter++;
	c.notify_one();
}

void semaphore::down()
{
	unique_lock lk(m);
	while (counter == 0)
		c.wait(lk);

	counter--;
}
