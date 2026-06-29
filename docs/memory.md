# Memory

Knot v0.1 keeps the public API bounded.

## Public buffers

```cpp
KNOT_MAX_SALT_LENGTH
KNOT_MAX_HASH_LENGTH
```

Use these constants when allocating caller-owned output buffers.

## Result buffers

`KnotSaltResult` and `KnotHashResult` contain fixed-size `value` arrays. They do not expose heap-owned strings.

## Internal buffers

Hashing uses stack buffers for the raw salt and derived key. Sensitive derived-key buffers are wiped before returning.

## Tasks

Knot does not create a FreeRTOS task in v0.1. Hashing is synchronous. Use Worker or your own task if password hashing should not run on the caller's task.

Initialize and deinitialize Knot during application lifecycle setup/teardown. Do not call `init()` or `deinit()` concurrently with login, hashing, comparison, or metadata flows from other FreeRTOS tasks.

When `useMutex` is enabled, public methods that read Knot state take the internal FreeRTOS recursive mutex. The mutex blocks until it is available on ESP32.

## PSRAM

Knot does not use PSRAM in v0.1 because the core operation uses small fixed buffers.

## Benchmarking

Use `examples/Benchmark` to measure hash time, compare time, and free heap before choosing a production cost. Bulk provisioning may also need salt generation timing because each generated salt uses the crypto backend's random source.
