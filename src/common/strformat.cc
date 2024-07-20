#include "strformat.h"

using namespace std;


string format_size_si(size_t size)
{
	const char* prefixes[] = {"", "k", "M", "G", "T", "P", "E"};
	int i = 0;
	size_t div = 1;
	for (; i < 7 && (size / div) > 1000; i++)
		div *= 1000;

	char buf[16];
	snprintf(buf, sizeof(buf), "%.2f %sB", (double) size / div, prefixes[i]);
	buf[sizeof(buf)-1] = '\0';

	return string(buf);
}

string format_size_bin(size_t size)
{
	const char* prefixes[] = {"", "k", "M", "G", "T", "P", "E"};
	int i = 0;
	size_t div = 1;
	for (; i < 7 && (size / div) > 1024; i++)
		div *= 1024;

	char buf[16];
	snprintf(buf, sizeof(buf), "%.2f %siB", (double) size / div, prefixes[i]);
	buf[sizeof(buf)-1] = '\0';

	return string(buf);
}

string format_hexstr(const char* buf, size_t size)
{
	string s;
	s.reserve(size * 2);

	for (size_t i = 0; i < size; i++)
	{
		char tmp[3];
		snprintf(tmp, sizeof(tmp), "%02x", (unsigned) ((unsigned char*) buf)[i]);
		s += string(tmp, 2);
	}

	return s;
}
