
#ifndef __CF_LOG_H_
#define  __CF_LOG_H_

#include "cf_core.h"

const char LOGLEVEL_ERROR = 0;
const char LOGLEVEL_WARN = 1;
const char LOGLEVEL_INFO = 2;
const char LOGLEVEL_DEBUG = 3;
const char LOGLEVEL_TRACE = 4;
typedef const char LogLevel;

/// Tells the core to log a message on behalf of a plugin
typedef void (*LogCb)(const CoreCtx* const, LogLevel log_level, const unsigned char *msg, const size_t msg_len);

#endif //__CF_LOG_H_