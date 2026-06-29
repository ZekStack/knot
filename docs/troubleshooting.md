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

## Hashing feels slow

Move hashing to a background task if the caller cannot block. Cost 14 is the secure default and may be slow on ESP32 targets; lower it only after measuring the latency and denial-of-service tradeoff on real hardware.
