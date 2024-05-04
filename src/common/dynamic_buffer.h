/* Smart dynamic buffer; it is not zero'd on creation / extension */
#ifndef __COMMON_DYNAMIC_BUFFER_H
#define __COMMON_DYNAMIC_BUFFER_H

#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <list>
#include <mutex>
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


class dynamic_aligned_buffer
{
protected:
	char* buf = nullptr;
	size_t _alignment;
	size_t _size;

	size_t to_power_of_two(size_t v)
	{
		size_t p = 1;
		while (p < v && p < std::numeric_limits<size_t>::max() / 2)
			p *= 2;

		if (p < v)
			p = v;

		return p;
	}

public:
	dynamic_aligned_buffer()
		: buf(nullptr), _alignment(0), _size(0)
	{
	}

	dynamic_aligned_buffer(size_t alignment, size_t initial_size)
		: _alignment(alignment), _size(to_power_of_two(initial_size))
	{
		buf = (char*) aligned_alloc(_alignment, _size);
		if (!buf)
			throw std::bad_alloc();
	}

	dynamic_aligned_buffer(dynamic_aligned_buffer&) = delete;
	dynamic_aligned_buffer& operator=(dynamic_aligned_buffer&) = delete;

	dynamic_aligned_buffer(dynamic_aligned_buffer&& o)
		: buf(o.buf), _alignment(o._alignment), _size(o._size)
	{
		o.buf = nullptr;
		o._alignment = 0;
		o._size = 0;
	}

	dynamic_aligned_buffer& operator=(dynamic_aligned_buffer&& o)
	{
		if (buf)
			free(buf);

		buf = o.buf;
		_alignment = o._alignment;
		_size = o._size;

		o.buf = nullptr;
		o._alignment = 0;
		o._size = 0;

		return *this;
	}

	operator bool() const
	{
		return buf != nullptr;
	}

	bool operator==(const dynamic_aligned_buffer& o)
	{
		return buf != nullptr && buf == o.buf;
	}

	char* ptr()
	{
		return buf;
	}

	size_t alignment()
	{
		return _alignment;
	}

	size_t size()
	{
		return _size;
	}

	void ensure_size(size_t s)
	{
		if (!buf)
		{
			throw std::runtime_error("An unallocated dynamic_aligned_buffer "
					"cannot be allocated through ensure_size.");
		}

		if (_size < s)
		{
			size_t new_size = _size;
			while (new_size < s && new_size < std::numeric_limits<size_t>::max() / 2)
				new_size *= 2;

			if (new_size < s)
				new_size = s;

			char* new_buf = (char*) aligned_alloc(_alignment, new_size);
			if (!new_buf)
				throw std::bad_alloc();

			memcpy(new_buf, buf, _size);

			char* old_buf = buf;
			buf = new_buf;
			_size = new_size;
			free(old_buf);
		}
	}

	virtual ~dynamic_aligned_buffer()
	{
		if (buf)
			free(buf);
	}
};

class dynamic_aligned_buffer_pool
{
protected:
	std::mutex m;
	size_t alignment;
	size_t max_size;

	std::list<dynamic_aligned_buffer> free_list;

public:
	dynamic_aligned_buffer_pool(size_t alignment, size_t max_size = 8)
		: alignment(alignment), max_size(max_size)
	{
	}

	dynamic_aligned_buffer get_buffer(size_t size)
	{
		std::unique_lock lk(m);

		if (size < alignment)
			size = alignment;

		/* Find smallest buffer of required size */
		auto i = free_list.begin();

		auto chosen = free_list.end();
		ssize_t overhead = std::numeric_limits<ssize_t>::max();

		for (; i != free_list.end(); i++)
		{
			ssize_t diff = i->size() - size;
			if (diff >= 0 && diff < overhead)
			{
				diff = overhead;
				chosen = i;
			}
		}

		if (chosen != free_list.end())
		{
			auto buf = std::move(*chosen);
			free_list.erase(chosen);
			return buf;
		}
		else
		{
			return dynamic_aligned_buffer(alignment, size);
		}
	}

	void return_buffer(dynamic_aligned_buffer&& buf)
	{
		/* Do not return unallocated buffers */
		if (!buf)
			return;

		std::unique_lock lk(m);

		if (find(free_list.begin(), free_list.end(), buf) == free_list.end())
			free_list.emplace_back(std::move(buf));

		/* Delete smallest buffer if the pool is too big */
		while (free_list.size() > max_size)
		{
			auto i = free_list.begin();
			auto smallest = i;

			for (; i != free_list.end(); i++)
			{
				if (i->size() < smallest->size())
					smallest = i;
			}

			free_list.erase(smallest);
		}
	}
};

#endif /* __COMMON_DYNAMIC_BUFFER_H */
