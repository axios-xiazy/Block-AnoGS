# Unit tests

GoogleTest-based unit tests for `block-anogs.hpp`.

## Build & run

```bash
sudo apt-get install -y cmake g++ libgtest-dev   # one-time
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

## What is covered

| File | Functions under test |
|------|----------------------|
| `test_library_info.cpp` | `parseProcMaps`, `hasExecutableMapping` (`/proc/self/maps` parsing) |
| `test_file_ops.cpp` | `lockFilePermissions`, `slowFileRead`, `exhaustFileDescriptors` |
| `test_memory.cpp` | `destroyElfHeaders`, `hideSectionHeaders`, `installGuardPages` |
| `test_signals.cpp` | `setupSignalHandlers`, `sigTrapHandler`, `dlPhdrCallback`, `hideFromLinkMap` |
| `test_seccomp.cpp` | `installSeccompFilter`, `preventPtrace`, `setupAntiDebug` |

Functions that irreversibly mutate process state (seccomp jail, `PTRACE_TRACEME`,
rlimit/fd exhaustion) and the page-guard fault are exercised in forked child
processes so the test runner itself is never affected.

`nukeLibrary` (the top-level orchestrator) and `installWatchdog` (an infinite
monitoring loop) are intentionally not unit tested — they compose the helpers
above and cannot be run safely in-process.

## Note on architecture support

The header originally compiled only for `__aarch64__` / `__arm__`. An
`__x86_64__` syscall-number block was added so the test suite can build and run
on standard x86-64 CI machines and developer workstations.
