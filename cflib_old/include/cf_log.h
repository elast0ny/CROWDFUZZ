
#ifndef __CF_LOG_H_
#define  __CF_LOG_H_

#include "cf_core.h"

#define LOGLEVEL_ERROR 0
#define LOGLEVEL_WARN 1
#define LOGLEVEL_INFO 2
#define LOGLEVEL_DEBUG 3
#define LOGLEVEL_TRACE 4
typedef const unsigned int LogLevel;

#define LOG_DYN(__core__, ...) (__core__)->log(__core__->ctx, __VA_ARGS__)
#define LOG(__core__, __level__, __str__) (__core__)->log(__core__->ctx, __level__, __str__, sizeof(__str__) - 1)
/// Tells the core to log a message on behalf of a plugin
typedef void (*LogCb)(const CoreCtx* const, LogLevel log_level, const char *msg, const size_t msg_len);

#endif //__CF_LOG_H_