#ifndef __CF_STAT_H_
#define  __CF_STAT_H_

// Prefixes to help interpretation of stats by ui/humans
/// Represents a total (can be added with same tags from other instances)
#define TAG_PREFIX_TOTAL "total_"
/// Represents an average (can be combined with same tags from other instances)
#define TAG_PREFIX_AVERAGE "avg_"

// Postfixes to give unit hint for ui/humans
/// Bytes should be represented as hex values
#define BYTES_POSTFIX_HEX "_hex"
/// String is a directory
#define STR_POSTFIX_DIR "_dir"
/// Number is seconds since EPOCH
#define NUM_POSTFIX_EPOCHS "_epoch_s"
/// Number is microseconds
#define NUM_POSTFIX_US "_us"
/// Number is milliseconds
#define NUM_POSTFIX_MS "_ms"
/// Number is seconds
#define NUM_POSTFIX_SEC "_s"
/// Number is minutes
#define NUM_POSTFIX_MIN "_m"
/// Number is hours
#define NUM_POSTFIX_HOUR "_h"

// Statistic types
const char STAT_NEWCOMPONENT = 0;
const char STAT_BYTES = 1;
const char STAT_STR = 2;
const char STAT_NUMBER = 3;
typedef const char StatType;

// Core states
const char CORE_INITIALIZING = 0;
const char CORE_FUZZING = 1;
const char CORE_EXITING = 2;
typedef const char CoreState;

typedef struct {
    unsigned int stat_len;
    unsigned int pid;
    CoreState state;
} StatFileHeader;

// Stat header layout in memory
typedef struct {
    char stat_type;
    unsigned short tag_len;
} StatHeader;

// Stat header that contains dynamicaly sized data
typedef struct {
    StatHeader header;
    unsigned short data_len;
} StatHeaderDyn;

///Requests memory space for a stat item from the core
typedef void* (*AddStatCb)(const CoreCtx* const, const unsigned char *tag, const unsigned short tag_len, StatType stat_type, const unsigned short size_required);

#endif
