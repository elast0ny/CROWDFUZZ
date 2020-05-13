# Plugin Development

CROWDFUZZ plugins can currently be written in any language that can generate native shared libraries and have support for C apis. The fuzzer core is written in Rust but exposes C callbacks so using either of these languages is highly recommended.

## Guidelines

### __Logging__ ([cf_log.h](../cflib/include/cf_log.h))

Plugins should avoid writing directly to STDOUT and instead use the `core->log` callback.

### __Stats__ ([cf_stats.h](../cflib/include/cf_stat.h))
Plugins can request statistic memory which will be available to frontends. This is done through `core->add_stat` . This callbacks returns a pointer to shared memory which can be directly accessed by other processes. In order to provide type hints to frontends, you can add tag name prefixes and postfixes.


### __Public store__ ([cf_store.h](../cflib/include/cf_store.h))
Plugins can share data between themselves through the public store. The store's structure is a hashmap of lists so item lookup is decently quick although it is still recommended to avoid querying the public store during fuzzing loops. With that being said, plugins should try to insert items only once and maintain the lifetime of the item for the duration of the process.

Plugins are expected to add the items they own/output during their `init()` procedure and should validate that their required inputs are present in their `validate()` procedure. Plugins should also cleanup the items they own in their `destroy()` procedure.

Plugins should use `CFTuple` structs when inserting buffers/strings into the store with the `CFTuple.first` containing the buffer length and `.second` containing a pointer to the buffer. `CFVec` is also available to store lists.

### __Private store__
Every plugin can store a pointer to private data during its `init()` procedure. Subsequent calls to their other exported functions will have this pointer as the second parameter.

# Examples

## Existing plugins
- [basic_select](../plugins/basic_select/)
- [basic_mutate](../plugins/basic_mutate/)
- [basic_run](../plugins/basic_run/)
- [basic_postrun](../plugins/basic_postrun/)

## Required boilerplate code
__Rust__

Cargo.toml
```toml
[lib]
crate-type = ["cdylib"] # Compile to native lib
[dependencies]
cflib = "0.*"
```
lib.rs
```Rust
cflib::register!(name, "my_better_plugin");
cflib::register!(init, my_init_function);
// etc...
```
__C/C++__

main.c
```C
// -I cflib/include/
#include <cflib.h>
//<...>
__declspec(dllexport) const char *__PluginName = "my_better_plugin";
__declspec(dllexport) PluginInitCb __PluginInitFnPtr = init;
__declspec(dllexport) PluginDoWorkCb __PluginDoWorkFnPtr = do_work;
// etc...
```