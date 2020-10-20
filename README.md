# CROWDFUZZ
A plugin based fuzzer core

![](cf_tui/doc/cf_tui_demo.gif)

(Terminal based frontend [cf_tui](cf_tui/))


## Why Another Fuzzer
This fuzzer does not bring any novel techniques to fuzzing on its own. The goal is to create a flexible and performant fuzzer __core__ that implements common functionalities that every fuzzer out there implements (folder management, UI, statistics, automation/deployement...) and allow researchers to focus their efforts on fuzzing related work (file mutation, testcase generation, faster process spawning...).

## Features
(Features provided by the core regardless of used plugins)
- Cross platform (Tested on Windows & Linux)
- Does not do __any__ (disk/terminal/network) I/O during fuzz loop
- Provide basic niceties
  - Ability to spawn itself multiple times
  - Bind to free CPUs
- Expose basic stats by default
  - Runtime information (uptime, core time, plugin time, etc...)
  - Project info (fuzz command, project folder, etc...)
- Allow stat extensions
  - Plugins can have their own arbitrary stats
- Provides a store for inter-plugin data sharing


## Frontends
|Name | Status | Description |
|-----|--------|-------------|
|[cf_tui](cf_tui/)| Done | Basic terminal based UI to monitor fuzzers on a local machine|
| ? | TODO | Web based fuzzer stat aggregator to see multiple fuzzers from multiple servers fuzzing the same project |

## List of Plugins

|Name | Status | Description |
|-----|--------|-------------|
|basic| Done |Very basic set of plugins. Should be used as reference/examples. See : [basic_select](plugins/basic_select/), [basic_mutate](plugins/basic_mutate/), [basic_run](plugins/basic_run/), [basic_postrun](plugins/basic_postrun/) |
|afl-fuzz| TODO | Standalone plugin suite that re-implements [afl-fuzz](http://lcamtuf.coredump.cx/afl/)|
|winafl| Working PoC | Implement the execution technique from [winAFL](https://github.com/ivanfratric/winafl). Re-use `afl-fuzz` plugins for the rest|
