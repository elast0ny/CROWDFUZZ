#ifndef __CF_STAT_H_
#define  __CF_STAT_H_

// Statistic types
const char STAT_NEWCOMPONENT = 0;
const char STAT_BYTES = 1;
const char STAT_STR = 2;
const char STAT_USIZE = 3;
const char STAT_ISIZE = 4;
const char STAT_U8 = 5;
const char STAT_U16 = 6;
const char STAT_U32 = 7;
const char STAT_U64 = 8;
const char STAT_I8 = 9;
const char STAT_I16 = 10;
const char STAT_I32 = 11;
const char STAT_I64 = 12;
typedef const char StatType;

// Core states
const char CORE_INITIALIZING = 0;
const char CORE_FUZZING = 1;
const char CORE_EXITING = 2;
typedef const char CoreState;

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
typedef void* (*AddStatCb)(const CoreCtx* const, StatType stat_type, const unsigned char *tag, const unsigned short tag_len, const unsigned short size_required);

#endif