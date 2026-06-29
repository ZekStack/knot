# Configuration

`KnotConfig` controls cost validation, password length, mutex use, and comparison behavior.

```cpp
KnotConfig config;
config.defaultCost = 10;
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
| `defaultCost` | `10` | Cost used by `hash(password)` and `genSalt()`. |
| `minCost` | `4` | Lowest accepted cost. |
| `maxCost` | `16` | Highest accepted cost. |
| `maxPasswordLength` | `72` | Maximum password byte length. |
| `useMutex` | `true` | Guards public methods with a FreeRTOS recursive mutex on ESP32. |
| `useConstantTimeCompare` | `true` | Uses constant-time comparison for derived keys. |

`defaultCost` must be inside `[minCost, maxCost]`.

## Cost

Cost is Knot's work factor. Higher cost means slower hashing and more expensive offline guessing.

In v0.1, cost maps to PBKDF2 iterations as:

```txt
iterations = 1000 * 2^(cost - 4)
```

Tune the value on the exact ESP32 board and firmware profile used by the product.
