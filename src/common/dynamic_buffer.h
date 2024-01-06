/* Smart dynamic buffer; it is not zero'd on creation / extension */
#ifndef __COMMON_DYNAMIC_BUFFER_H
#define __COMMON_DYNAMIC_BUFFER_H

#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <new>

class dynamic_buffer
{
protected:
	char* buf = nullptr;
	size_t _size = 0;

public:
	dynamic_buffer()
	{
	}

	dynamic_buffer(dynamic_buffer&) = delete;
	dynamic_buffer& operator=(dynamic_buffer&) = delete;

	dynamic_buffer(dynamic_buffer&& o)
		: buf(o.buf), _size(o._size)
	{
		o.buf = nullptr;
		o._size = 0;
	}

	dynamic_buffer& operator=(dynamic_buffer&& o)
	{
		if (buf)
			free(buf);

		buf = o.buf;
		_size = o._size;

		o.buf = nullptr;
		o._size = 0;

		return *this;
	};

	void ensure_size(size_t s)
	{
		if (_size < s)
		{
			size_t new_size = _size > 0 ? _size : 1;

			while (new_size < s)
			{
				if (new_size >= std::numeric_limits<size_t>::max() / 2)
					throw std::overflow_error("size too large");

				new_size *= 2;
			}

			auto new_buf =  (char*) realloc(buf, new_size);
			if (!new_buf)
				throw std::bad_alloc();

			buf = new_buf;
			_size = new_size;
		}
	}

	size_t size() const
	{
		return _size;
	}

	char* ptr()
	{
		return buf;
	}

	virtual ~dynamic_buffer()
	{
		if (buf)
			free(buf);
	}
};

#endif /* __COMMON_DYNAMIC_BUFFER_H */
