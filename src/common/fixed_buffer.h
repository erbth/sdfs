/* Smart buffers; they are not zero'd on creation */
#ifndef __COMMON_FIXED_BUFFER_H
#define __COMMON_FIXED_BUFFER_H

#include <cstdlib>
#include <cstring>
#include <new>

class fixed_buffer
{
protected:
	char* buf = nullptr;
	size_t size;

public:
	fixed_buffer()
		: size(0)
	{
	}

	fixed_buffer(size_t size)
		: size(size)
	{
		buf = (char*) malloc(size);
		if (!buf)
			throw std::bad_alloc();
	}

	fixed_buffer(fixed_buffer&) = delete;
	fixed_buffer& operator=(fixed_buffer&) = delete;

	fixed_buffer(fixed_buffer&& o)
		: buf(o.buf), size(o.size)
	{
		o.buf = nullptr;
		o.size = 0;
	}

	fixed_buffer& operator=(fixed_buffer&& o)
	{
		if (buf)
			free(buf);

		buf = o.buf;
		size = o.size;

		o.buf = 0;
		o.size = 0;

		return *this;
	};

	operator bool() const
	{
		return buf != nullptr;
	}

	char* ptr()
	{
		return buf;
	}

	size_t get_size()
	{
		return size;
	}

	virtual ~fixed_buffer()
	{
		if (buf)
			free(buf);
	}
};

class fixed_aligned_buffer
{
protected:
	char* buf = nullptr;
	size_t alignment;
	size_t size;

public:
	fixed_aligned_buffer()
		: buf(nullptr), alignment(0), size(0)
	{
	}

	fixed_aligned_buffer(size_t alignment, size_t size)
		: alignment(alignment), size(size)
	{
		buf = (char*) aligned_alloc(alignment, size);
		if (!buf)
			throw std::bad_alloc();

		memset(buf, 0, size);
	}

	fixed_aligned_buffer(fixed_aligned_buffer&) = delete;
	fixed_aligned_buffer& operator=(fixed_aligned_buffer&) = delete;

	fixed_aligned_buffer(fixed_aligned_buffer&& o)
		: buf(o.buf), alignment(o.alignment), size(o.size)
	{
		o.buf = nullptr;
		o.alignment = 0;
		o.size = 0;
	}

	fixed_aligned_buffer& operator=(fixed_aligned_buffer&& o)
	{
		if (buf)
			free(buf);

		buf = o.buf;
		alignment = o.alignment;
		size = o.size;

		o.buf = nullptr;
		o.alignment = 0;
		o.size = 0;

		return *this;
	}

	operator bool() const
	{
		return buf != nullptr;
	}

	char* ptr()
	{
		return buf;
	}

	size_t get_alignment()
	{
		return alignment;
	}

	size_t get_size()
	{
		return size;
	}

	virtual ~fixed_aligned_buffer()
	{
		if (buf)
			free(buf);
	}
};

#endif /* __COMMON_FIXED_BUFFER_H */
