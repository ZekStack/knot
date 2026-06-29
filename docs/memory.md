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

## PSRAM

Knot does not use PSRAM in v0.1 because the core operation uses small fixed buffers.
