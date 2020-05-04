
#ifndef __CF_STORE_H_
#define  __CF_STORE_H_

#include "cf_core.h"
#include "cflib.h"

/* List of store keys that should be used by plugins */

#define KEY_LEN(__key__) (sizeof(__key__)-1)

/// Input directory from the config
#define KEY_INPUT_DIR "input_dir"
/// Output directory from the config
#define KEY_STATE_DIR "state_dir"
/// Result directory from the config
#define KEY_RESULT_DIR "results_dir"
/// Target binary being fuzzed
#define KEY_TARGET_PATH "target_bin"
/// Target arguments
#define KEY_TARGET_ARGS "target_args"
/// Number of last runs to count for averages
#define KEY_AVG_DENOMINATOR "avg_denominator"
/// Number of the current exec in progress
#define KEY_CUR_EXEC_NUM "num_execs"
/// Working directory of the project
#define KEY_CWD "cwd"
/// Name of the fuzzer
#define KEY_FUZZER_ID "fuzzer_id"
/// Extra plugin config values
#define KEY_PLUGIN_CONF "plugin_conf"

/// Selected file for the next fuzz iteration
#define KEY_INPUT_PATH "input_path"
/// Bytes from the selected input file (type CVec)
#define KEY_INPUT_BYTES "input_bytes"
/// Mutated testcase ready for the target (type CVec, buffer contains a list of (len:usize, ptr:c_void) tuples pointing to chuncks of memory that need to be stitched together before passing to the target)
#define KEY_CUR_INPUT_CHUNKS "cur_input_chunks"
/// Name of the file created on disk after mutation
#define KEY_CUR_INPUT_PATH "cur_input_path"

/// List of *CVec 
#define KEY_NEW_INPUT_LIST "new_inputs"

/// Exit status of the the target after running it with KEY_CUR_INPUT
/// This key should be a CTuple with `first` set to EXIT_STATUS_* , and `second` set to the value
#define KEY_EXIT_STATUS "exit_status"
#define EXIT_STATUS_NORMAL 0
#define EXIT_STATUS_TIMEOUT 1
#define EXIT_STATUS_CRASH 2

/* Complex types that can be stored in the store */

/// Desbribes a buffer of variable length and capacity
typedef struct __attribute__((packed)) {
    /// Number of items currently in use in *data
    size_t length;
    /// Number of items available in *data
    size_t capacity;
    /// Pointer to the allocation
    void *data;
} CVec;

/// Basic struct to define tuples
typedef struct __attribute__((packed)) {
    size_t first;
    size_t second;
} CTuple;

/* Methods that allow interaction with the store */

#define PUSH_BACK(__core__, __const_str__, __data__) (__core__)->store_push_back(__core__->ctx, __const_str__, sizeof(__const_str__) - 1, __data__)
#define PUSH_FRONT(__core__, __const_str__, __data__) (__core__)->store_push_front(__core__->ctx, __const_str__, sizeof(__const_str__) - 1, __data__)
#define POP_BACK(__core__, __const_str__) (__core__)->store_pop_back(__core__->ctx, __const_str__, sizeof(__const_str__) - 1)
#define POP_FRONT(__core__, __const_str__) (__core__)->store_pop_front(__core__->ctx, __const_str__, sizeof(__const_str__) - 1)
#define STORE_GET(__core__, __const_str__, __idx__) (__core__)->store_get_mut(__core__->ctx, __const_str__, sizeof(__const_str__) - 1, __idx__)
#define STORE_LEN(__core__, __const_str__) (__core__)->store_len(__core__->ctx, __const_str__, sizeof(__const_str__) - 1)

///Appends a value to key's vector
typedef void (*StorePush)(const CoreCtx* const, const char *key, const size_t key_len, void *data_ptr);
///Pops a value from key's vector
typedef void* (*StorePop)(const CoreCtx* const, const char *key, const size_t key_len);
///Get a reference to an item at 'index' from key's vector
typedef void* (*StoreGetMut)(const CoreCtx* const, const char *key, const size_t key_len, size_t index);
///Returns the number of elements in key's vector
typedef size_t (*StoreLen)(const CoreCtx* const, const char *key, const size_t key_len);

#endif //__CF_STORE_H_