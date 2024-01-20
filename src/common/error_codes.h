#ifndef __COMMON_ERROR_CODES_H
#define __COMMON_ERROR_CODES_H

namespace err
{
enum error_code : int
{
	SUCCESS = 0,
	IO,
	NOENT,
	INVAL
};
};

#endif /* __COMMON_ERROR_CODES_H */
