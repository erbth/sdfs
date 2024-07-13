#ifndef __COMMON_LOGGING_H
#define __COMMON_LOGGING_H

#ifdef DEBUG
#define debug(fmt, ...) printf("\033[95mDEBUG:\033[0m " fmt, ## __VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#endif /* __COMMON_LOGGING_H */
