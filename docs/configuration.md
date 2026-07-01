# Configuration

`KnotConfig` controls cost validation, password length, mutex use, and comparison behavior.

```cpp
KnotConfig config;
config.defaultCost = 14;
config.minCost = 4;
config.maxCost = 16;
config.maxPasswordLength = 72;
config.useMutex = true;
config.useConstantTimeCompare = true;

KnotResult result = knot.init(config);
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `defaultCost` | `14` | Cost used by `hash(password)` and `genSalt()`. |
| `minCost` | `4` | Lowest accepted cost. |
| `maxCost` | `16` | Highest accepted cost. |
| `maxPasswordLength` | `72` | Maximum password byte length. |
| `useMutex` | `true` | Guards public methods with a FreeRTOS recursive mutex on ESP32. |
| `useConstantTimeCompare` | `true` | Uses constant-time comparison for derived keys. |

`defaultCost` must be inside `[minCost, maxCost]`.

`maxPasswordLength` is configurable downward in v0.1, but it cannot exceed `KNOT_MAX_PASSWORD_LENGTH` (`72`). `init()` rejects `0` and any value above that ceiling.

## Cost

Cost is Knot's work factor. Higher cost means slower hashing and more expensive offline guessing.

In v0.1, cost maps to PBKDF2 iterations as:

```txt
iterations = 1000 * 2^(cost - 4)
```

| Cost | PBKDF2-HMAC-SHA256 iterations |
| --- | ---: |
| 4 | 1,000 |
| 10 | 64,000 |
| 14 | 1,024,000 |
| 16 | 4,096,000 |

Cost 14 is the secure default, not the demo or test setting. Examples and host tests that need speed explicitly configure cost 4.

Production firmware must benchmark cost 14 on the exact ESP32 board and firmware profile used by the product. Lower the cost only with a documented latency and denial-of-service tradeoff.

Existing `$knot$v1$c10$...` hashes remain verifiable. They become rehash candidates when checked against the new default cost 14.
