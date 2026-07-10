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

Synchronous hashing uses stack buffers for the raw salt and derived key. Sensitive derived-key buffers are wiped before returning.

`KnotCompareOperation` owns fixed-size password, salt, expected-hash, `U`, accumulated `T`, and derived-key-block buffers, plus a small backend HMAC context. Its implementation is allocated when the operation object is constructed. Sensitive operation state is securely wiped on completion, failure, cancellation, reuse, and destruction.

## Tasks

Knot does not create a FreeRTOS task. `hash()` and `compare()` are synchronous convenience methods. Use `beginCompare()` and bounded `step()` calls when comparison must cooperate with request handling, Worker, or another scheduler.

`beginCompare()` takes Knot's internal mutex only while validating inputs and copying the required configuration and hash state. The operation does not retain the mutex while it is between steps, sleeping, or executing PBKDF2 iterations.

Initialize and deinitialize Knot during application lifecycle setup/teardown. An already-started compare operation owns its state and can finish after Knot is deinitialized, but no new operation can begin until Knot is initialized again.

When `useMutex` is enabled, public methods that read Knot state take the internal FreeRTOS recursive mutex. The mutex blocks until it is available on ESP32. A single `KnotCompareOperation` must still be owned by one task at a time; do not call `step()` and `cancel()` concurrently.

## PSRAM

Knot does not use PSRAM in v0.1 because the core operation uses small fixed buffers.

## Benchmarking

Use `examples/Benchmark` to measure hash time, compare time, and free heap before choosing a production cost. Use `examples/CooperativeCompare` to start tuning an iteration budget, then measure each `step()` on the target and aim for the application's responsiveness window, typically about 5-20 ms. Bulk provisioning may also need salt generation timing because each generated salt uses the crypto backend's random source.
