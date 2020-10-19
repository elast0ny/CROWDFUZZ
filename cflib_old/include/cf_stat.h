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

#define STAT_TAG_TARGET_EXEC_TIME TAG_PREFIX_AVERAGE "target_exec_time" NUM_POSTFIX_US

// Statistic types
#define STAT_NEWCOMPONENT 0
#define STAT_BYTES 1
#define STAT_STR 2
#define STAT_NUMBER 3
typedef const char StatType;

// Core states
#define CORE_INITIALIZING 0
#define CORE_FUZZING 1
#define CORE_EXITING 2
typedef const unsigned int CoreState;

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

#define ADD_STAT(__core__, __const_tag__, ...) (__core__)->add_stat(__core__->ctx, __const_tag__, sizeof(__const_tag__) - 1, __VA_ARGS__)
///Requests memory space for a stat item from the core
typedef void* (*AddStatCb)(const CoreCtx* const, const char *tag, const unsigned short tag_len, StatType stat_type, const unsigned short size_required);

#endif
