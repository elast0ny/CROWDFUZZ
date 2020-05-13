## save_result

This plugin saves any crash or timeout in the project's result directory.

The plugin only saves files with unique content and maintains the structure : 
```bash
# Crashing inputs
crashes/[code]_[sha1]
# Timing out inputs
timeouts/[sha1]
```



## Plugin Inputs
|key|Description|
|----|----|
|KEY_EXIT_STATUS|Will save file if set to crash or timeout|
|KEY_CUR_INPUT_CHUNKS|Used to build a hash of the file when saving to disk|
|KEY_ONLY_EXEC_MODE|Will not perform any actions if this key is set to CF_TRUE|
  

## Plugin Outputs
None