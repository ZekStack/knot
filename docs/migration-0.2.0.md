# Migrating to Knot 0.2.0

Knot 0.2.0 adopts Strata v0.1.3 for Knot-owned dynamic memory and FreeRTOS synchronization storage.

## Hash compatibility

There is no stored-password migration.

Knot 0.2.0 continues to read and write the existing:

```text
$knot$v1$c<cost>$<salt>$<hash>
```

format with the same PBKDF2-HMAC-SHA256 behavior. Library version 0.2.0 does not change the encoded `v1` hash format.

## New dependency

Knot now depends on Strata v0.1.3. PlatformIO resolves it through `library.json`. Arduino IDE users must install both Knot and Strata.

## Configuration

Existing field-by-field configuration continues to work. Knot adds the shared ZekStack memory policy:

```cpp
KnotConfig config;
config.memory.allocation = Strata::Placement::Default;
config.memory.taskStack = Strata::Placement::Internal;
```

The default preserves the v0.1 allocation behavior. Knot does not become PSRAM-first.

Use `Internal`, `PreferExternal`, or `RequireExternal` only when the application has a deliberate placement requirement. `RequireExternal` fails instead of falling back.

## Cooperative operations

`KnotCompareOperation` now allocates its private state lazily on `beginCompare()`. This means constructing an unused operation no longer allocates heap memory.

Inactive operations remain reusable. Reusing one with a Knot instance configured for a different placement safely re-homes its storage.

## Error handling

`KnotCode::AllocationFailed` is new and reports Strata-owned allocation failures separately from cryptographic failures.

## Diagnostics

Use `Knot::getDiagnostics()` and `KnotCompareOperation::getDiagnostics()` to inspect requested placement and observed memory regions.
