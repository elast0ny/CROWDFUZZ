
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
/// Working directory of the project
#define KEY_CWD "cwd"

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
/// This key should be a CTuple with `first` set to the status type, and `second` set to the value
#define KEY_EXIT_STATUS "exit_status"

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

///Appends a value to key's vector
typedef void (*StorePush)(const CoreCtx* const, const unsigned char *key, const size_t key_len, void *data_ptr);
///Pops a value from key's vector
typedef void* (*StorePop)(const CoreCtx* const, const unsigned char *key, const size_t key_len);
///Get a reference to an item at 'index' from key's vector
typedef void* (*StoreGetMut)(const CoreCtx* const, const unsigned char *key, const size_t key_len, size_t index);
///Returns the number of elements in key's vector
typedef size_t (*StoreLen)(const CoreCtx* const, const unsigned char *key, const size_t key_len);

#endif //__CF_STORE_H_