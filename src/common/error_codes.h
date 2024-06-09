#ifndef __COMMON_ERROR_CODES_H
#define __COMMON_ERROR_CODES_H

/* NOTE: These definitions are doubled in sdfs_ds.h; adapt there accordingly
 * when changing them here. */
namespace err
{
enum error_code : int
{
	SUCCESS = 0,
	IO,
	NOENT,
	INVAL,
	NOTDIR,
	NOSPC,
	NAMETOOLONG,
	ISDIR,
	NXIO
};
};

#endif /* __COMMON_ERROR_CODES_H */
