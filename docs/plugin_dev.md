# Plugin Development

If you are interested in developing your own plugins, take a look at the plugins/ folder for examples.

All of the common store key definitions reside in [cflib/src/store.rs](../cflib/src/store.rs)


## Store guidelines
Plugins should generaly add references to the store during their load() and keep those references alive until unload(). This enables other plugins to only have to query the store once during validation() and subsequently just use the saved reference.

In general, you should make sure that the struct you are referencing is either Box'ed or a child of a box'ed struct. Make sure to never store  the result of functions such as `String.as_str()`, `vec.as_slice()`, etc.. as they create temporary fat pointers to the owned struct versus being real references to the owned struct.

## __Corpus management__
Plugins in this category should create/use the INPUT_LIST entry and the NEW_INPUTS entry if they accept new inputs.

For simplicity, it is highly recommend to avoid input deletion & reordering in this list so other plugins can use indexes safely.

## __File selection__
Responsible for creating the INPUT_BYTES and INPUT_IDX entries. File selectors must ensure that INPUT_BYTES is a CfInput with a single chunk for the whole file.

It should also aim to respect the RESTORE_INPUT and NO_SELECT keys.

## __Mutation__
Mutation plugins should read the INPUT_BYTES entry and push values to MUTATED_INPUT_BYTES.

It is also recommended for these plugins to obey the NO_MUTATE entry and not do anything if it is set to true. The NO_MUTATE should be used in conjunction with another arbitrary key in order to properly populate the MUTATED_INPUT_BYTES.
e.g.
```Rust
// disable all mutators
NO_MUTATE = true
// because we are doing afl calibration
AFL_CALIBRATION = true 
```

## __Execution__
Responsible for creating and updating TARGET_EXEC_TIME/AVG_TARGET_EXEC_TIME and EXIT_STATUS. This plugin should feed the contents of INPUT_BYTES to the target application.
