#ifndef __CF_PLUGIN_H_
#define  __CF_PLUGIN_H_

#include <stddef.h>
#include "cf_error.h"
#include "cf_core.h"
#include "cf_store.h"
#include "cf_log.h"
#include "cf_stat.h"

/// Context passed along to plugins providing an interface to the fuzzer functionalities
typedef struct __attribute__((packed)) {
    void *priv_data;
    StorePush store_push_back;
    StorePush store_push_front;
    StorePop store_pop_back;
    StorePop store_pop_front;
    StoreGetMut store_get_mut;
    StoreLen store_len;
    LogCb log;
    AddStatCb add_stat;

    const CoreCtx* const ctx;
} CoreInterface;

///Callback called once at plugin initialisation
///
///In this function, plugins should create the keys in the store that they control and
///set a pointer to their private data if needed.
typedef PluginStatus (*const  PluginInitCb)(CoreInterface *core_ptr);
///Callback called once to allow plugin to validate that all inputs are available to them
///
///This is a good time to take references to store values that are shared amongst plugins
typedef PluginStatus (*const  PluginValidateCb)(CoreInterface *core_ptr, void *priv_data);
///Callback called once per fuzz iteration
typedef PluginStatus (*const PluginDoWorkCb)(CoreInterface *core_ptr, void *priv_data);
///Callback called once at plugin teardown
typedef PluginStatus (*const PluginDestroyCb)(CoreInterface *core_ptr, void *priv_data);

#define SYMBOL_PLUGIN_NAME __PluginName
#define _SYMBOL_PLUGIN_NAME "__PluginName"

#define SYMBOL_PLUGIN_INIT __PluginInitFnPtr
#define _SYMBOL_PLUGIN_INIT "__PluginInitFnPtr"

#define SYMBOL_PLUGIN_VALIDATE __PluginValidateFnPtr
#define _SYMBOL_PLUGIN_VALIDATE "__PluginValidateFnPtr"

#define SYMBOL_PLUGIN_DOWORK __PluginDoWorkFnPtr
#define _SYMBOL_PLUGIN_DOWORK "__PluginDoWorkFnPtr"

#define SYMBOL_PLUGIN_DESTROY __PluginDestroyFnPtr
#define _SYMBOL_PLUGIN_DESTROY "__PluginDestroyFnPtr"

// Symbols that plugins need to define
extern const char SYMBOL_PLUGIN_NAME;
extern PluginInitCb SYMBOL_PLUGIN_INIT;
extern PluginValidateCb SYMBOL_PLUGIN_VALIDATE;
extern PluginDoWorkCb SYMBOL_PLUGIN_DOWORK;
extern PluginDestroyCb SYMBOL_PLUGIN_DESTROY;

#endif