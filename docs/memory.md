# Memory

Knot v0.2.0 routes Knot-owned dynamic allocations and synchronization storage through Strata v0.1.3 while preserving the bounded public API and existing password-hash format.

## Default policy

```cpp
KnotConfig config;
config.memory.allocation = Strata::Placement::Default;
config.memory.taskStack = Strata::Placement::Internal;
```

`memory.allocation` controls movable Knot-owned heap storage. `memory.taskStack` is part of the shared ZekStack memory-policy contract but is currently unused because Knot creates no FreeRTOS task.

Knot deliberately keeps `Default` as its allocation default. The Strata migration does not turn Knot into a PSRAM-first library.

## Ownership and placement

| Resource | Placement / owner |
| --- | --- |
| `KnotImpl` control state | Internal Strata allocation |
| recursive mutex control block | Internal through `Strata::FreeRTOS::RecursiveMutex` |
| `KnotCompareOperationImpl` | `memory.allocation` |
| Knot-owned HMAC wrapper context | operation `memory.allocation` |
| mbedTLS internal allocations | mbedTLS-owned, outside Knot's ownership boundary |
| synchronous salt/derived-key temporaries | caller task stack |
| parser/encoding scratch buffers | caller task stack |
| `KnotSaltResult` / `KnotHashResult` values | inline fixed arrays |
| caller-provided output buffers | caller-owned |

## Cooperative compare storage

A default-constructed `KnotCompareOperation` performs no heap allocation. Its private state is allocated lazily by `beginCompare()` using the current Knot instance's `memory.allocation` policy.

An inactive operation can be reused with another Knot instance. If the requested placement changes, Knot allocates replacement storage first, then securely clears and releases the old operation state. Allocation failure therefore leaves the previous inactive storage intact until a replacement exists.

`Strata::Placement::RequireExternal` is strict. If external memory is unavailable, Knot initialization fails with `KnotCode::AllocationFailed` instead of silently falling back.

## Sensitive data

Strata owns storage placement and lifetime mechanics. Knot remains responsible for secret handling.

Before Knot releases or re-homes owned cooperative-operation storage it clears:

- the copied password;
- salt and expected hash;
- PBKDF2 `U` and accumulated values;
- the derived-key block;
- the HMAC wrapper context.

Synchronous hashing continues to wipe raw salt and derived-key stack buffers before returning.

## Tasks

Knot does not create a FreeRTOS task. `hash()` and `compare()` remain synchronous convenience methods. Use `beginCompare()` and bounded `step()` calls when comparison must cooperate with request handling, Worker, or another scheduler.

The operation does not retain Knot's mutex while it is between steps or executing PBKDF2 iterations. An already-started compare operation owns its state and can finish after Knot is deinitialized.

## Diagnostics

`Knot::getDiagnostics()` reports the requested general allocation policy plus the observed regions for the internal implementation and mutex control storage.

`KnotCompareOperation::getDiagnostics()` reports whether storage exists, whether the operation is active, the requested placement, and observed regions for the operation and HMAC wrapper.

Requested `Strata::Placement` and observed `Strata::Region` are intentionally kept separate.

## Benchmarking

Use `examples/Benchmark` to measure hash time, compare time, and free heap before choosing a production cost. Use `examples/CooperativeCompare` to tune an iteration budget and aim for the application's responsiveness window, typically about 5-20 ms per `step()`.
