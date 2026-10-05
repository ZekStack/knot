# Troubleshooting

## `NotInitialized`

Call `knot.init()` before hashing, salt generation, or comparison.

## `InvalidCost`

The requested cost is outside the configured `[minCost, maxCost]` range.

## `InvalidSalt`

`hash(password, encodedSalt)` expects a salt string from `genSalt()`:

```txt
$knot$v1$c14$<salt>
```

It does not accept a full stored hash.

## `InvalidHash`

`compare()`, `getRounds()`, and `getInfo()` expect a full stored hash:

```txt
$knot$v1$c14$<salt>$<hash>
```

## `UnsupportedAlgorithm`

The string is not a Knot hash. Bcrypt hashes such as `$2b$...` are not accepted.

## `PasswordTooLong`

The password exceeds `config.maxPasswordLength`. The default is `72` bytes.

## `AllocationFailed`

Knot reports `AllocationFailed` when Strata cannot create Knot-owned runtime storage. With `memory.allocation = Strata::Placement::RequireExternal`, this also means external RAM is unavailable or cannot satisfy the request.

Use `Default`, `Internal`, or `PreferExternal` when strict external placement is not required. `Knot::getDiagnostics()` and `KnotCompareOperation::getDiagnostics()` expose requested placement separately from observed memory regions.

## Hashing feels slow

Move hashing to a background task if the caller cannot block. Cost 14 is the secure default and may be slow on ESP32 targets; lower it only after measuring the latency and denial-of-service tradeoff on real hardware.
