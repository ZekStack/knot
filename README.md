# Knot

Knot is a compact ESP32 password hashing library with a bcrypt-like self-contained hash string format, backed by PBKDF2-HMAC-SHA256.

Knot helps Arduino ESP32 projects create and verify self-contained password hashes with secure salt generation, cost-based PBKDF2-HMAC-SHA256 hashing, constant-time comparison, cooperative verification, and bounded result buffers.

[![CI](https://github.com/ZekStack/knot/actions/workflows/ci.yml/badge.svg)](https://github.com/ZekStack/knot/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZekStack/knot?sort=semver)](https://github.com/ZekStack/knot/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Why use Knot?

* **Password-focused** - generate salts, hash passwords, compare stored hashes, and detect old costs.
* **Self-contained hashes** - the encoded hash stores the algorithm marker, version, cost, salt, and derived key.
* **Cooperative verification** - split PBKDF2 comparison into bounded steps for FreeRTOS and Worker integration.
* **ESP32-friendly** - fixed public buffers, no exceptions, result-based errors, and optional mutex protection.
* **Familiar API shape** - `genSalt()`, `hash()`, `compare()`, and `getRounds()` helpers without bcrypt compatibility claims.
* **Clear compatibility** - Knot hashes are not bcrypt hashes and never use bcrypt `$2a$`, `$2b$`, or `$2y$` prefixes.

## Install

### PlatformIO

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
  https://github.com/ZekStack/knot.git

build_flags =
  -std=gnu++20
build_unflags =
  -std=gnu++11
```

### Arduino IDE

Knot is not published to Arduino Library Manager yet.

Install it by downloading the repository ZIP or cloning it into your Arduino libraries folder.

```txt
Arduino/libraries/Knot
```

## Quick start

```cpp
#include <Arduino.h>
#include <Knot.h>

Knot knot;

void setup() {
	Serial.begin(115200);

	KnotResult init = knot.init();
	if (!init) {
		Serial.println(init.message);
		return;
	}

	KnotHashResult hash = knot.hash("my-password");
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	KnotCompareResult check = knot.compare("my-password", hash.value);
	if (!check) {
		Serial.println(check.message);
		return;
	}

	Serial.println(check.match ? "valid" : "invalid");
}

void loop() {
	delay(1000);
}
```

## Cooperative compare

Use a stateful operation when verification must return control to FreeRTOS between bounded PBKDF2 slices.

```cpp
KnotCompareOperation operation;
KnotResult begin = knot.beginCompare(operation, password, encodedHash);

KnotStepResult step = operation.step(iterationBudget);
while (step.inProgress()) {
	vTaskDelay(1);
	step = operation.step(iterationBudget);
}

if (step.completed() && step.match) {
	login();
}
```

Benchmark `iterationBudget` on the target and aim for the application's responsiveness window, normally around 5-20 ms per `step()`. Call `operation.cancel()` between steps when a request or Worker job is cancelled.

## Important notes

> [!IMPORTANT]
> Knot uses PBKDF2-HMAC-SHA256, not bcrypt. Store and verify Knot hashes only with Knot.

* v0.1 hashes use `$knot$v1$c<cost>$<salt>$<hash>`.
* `v1` means PBKDF2-HMAC-SHA256 with a 16-byte salt and 32-byte derived key.
* Password input is limited to `KNOT_MAX_PASSWORD_LENGTH` bytes by default.
* Cost 14 is the secure default, not the demo setting. Tune cost on real target hardware.
* `hash()` and `compare()` are synchronous convenience APIs. Use `beginCompare()` and `step()` for cooperative verification.

## Examples

| Example | Description |
| --- | --- |
| `BasicHash` | Minimal init, hash, and compare. |
| `CooperativeCompare` | Verify a hash through bounded PBKDF2 steps. |
| `ExplicitCost` | Choose a cost and read rounds/cost. |
| `ManualSalt` | Generate a salt and pass it into `hash()`. |
| `CallerBuffer` | Use caller-owned buffers. |
| `NeedsRehash` | Upgrade stored hashes after login. |
| `HashInfo` | Read algorithm, version, and cost metadata. |
| `Configuration` | Configure password length and cost limits. |
| `ClassUsage` | Use Knot from an application class. |
| `Benchmark` | Print target, cost, iterations, timing, and heap measurements. |

Start with:

```txt
examples/BasicHash
```

## Documentation

Detailed documentation is available in the `docs/` folder.

| Document | Description |
| --- | --- |
| [`docs/getting-started.md`](docs/getting-started.md) | Setup and first password flow. |
| [`docs/configuration.md`](docs/configuration.md) | Config options and defaults. |
| [`docs/api.md`](docs/api.md) | Public classes, methods, and result types. |
| [`docs/examples.md`](docs/examples.md) | Explanation of all included examples. |
| [`docs/security.md`](docs/security.md) | Password hashing and storage notes. |
| [`docs/memory.md`](docs/memory.md) | Buffers, mutexes, and synchronous behavior. |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Common issues and fixes. |
| [`docs/bcrypt-positioning.md`](docs/bcrypt-positioning.md) | Bcrypt-like format and compatibility limits. |

## API overview

```cpp
Knot knot;
knot.init();

KnotSaltResult salt = knot.genSalt(14);
KnotHashResult hash = knot.hash("password", salt.value);
KnotCompareResult check = knot.compare("password", hash.value);

KnotRoundsResult cost = knot.getRounds(hash.value);
bool upgrade = knot.needsRehash(hash.value, 14);
```

For the full API, see [`docs/api.md`](docs/api.md).

## Compatibility

| Item | Support |
| --- | --- |
| Framework | Arduino ESP32 |
| Platform | `espressif32` |
| Language | C++20 |
| Filesystem | none |
| PSRAM | not used in v0.1 |
| Dependencies | mbedTLS from ESP32 platform |
| Exceptions | Not used |
| Status | Early-stage `0.1.0` |

## Configuration

```cpp
KnotConfig config;
config.defaultCost = 14;
config.minCost = 4;
config.maxCost = 16;
config.maxPasswordLength = 72;

KnotResult result = knot.init(config);
```

For all options, see [`docs/configuration.md`](docs/configuration.md).

Existing `$knot$v1$c10$...` hashes remain verifiable after the default cost change. They are treated as rehash candidates when checked against the new default cost 14.

## Error handling

Knot reports operation status through result objects.

```cpp
KnotHashResult hash = knot.hash("password");

if (!hash) {
	Serial.println(hash.message);
	return;
}
```

For result fields and status codes, see [`docs/api.md`](docs/api.md).

## License

MIT - see [`LICENSE.md`](LICENSE.md).

## ZekStack

Part of the ZekStack ESP32 library stack.
