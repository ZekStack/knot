# API

## Main class

```cpp
Knot knot;
```

Initialize before use:

```cpp
KnotResult result = knot.init();
```

## Hashing

```cpp
KnotHashResult hash = knot.hash("password");
KnotHashResult hash = knot.hash("password", 14);
KnotHashResult hash = knot.hash("password", encodedSalt);

const uint8_t password[] = {'p', 'a', 0x00, 's', 's'};
KnotHashResult binaryHash = knot.hash(password, sizeof(password), 14);
```

`hash(password)` and `hash(password, cost)` generate a fresh salt internally.

`hash(password, encodedSalt)` uses a salt produced by `genSalt()` or `genSalt(cost)`.

The `const char *` overloads hash bytes up to the first NUL byte. The `const uint8_t *` plus length overloads are binary-safe and can hash embedded NUL bytes.

`nullptr` passwords are invalid, including `nullptr, 0`. Empty passwords are valid with `hash("")` or a non-null byte pointer and length `0`.

## Salt generation

```cpp
KnotSaltResult salt = knot.genSalt();
KnotSaltResult salt = knot.genSalt(12);
```

The salt is encoded as:

```txt
$knot$v1$c12$<base64url-salt>
```

## Caller-owned buffers

```cpp
char salt[KNOT_MAX_SALT_LENGTH + 1];
KnotResult saltResult = knot.genSaltTo(10, salt, sizeof(salt));

char hash[KNOT_MAX_HASH_LENGTH + 1];
KnotResult hashResult = knot.hashTo("password", salt, hash, sizeof(hash));
KnotResult binaryResult = knot.hashTo(password, sizeof(password), 12, hash, sizeof(hash));
```

## Compare

```cpp
KnotCompareResult check = knot.compare("password", storedHash);
KnotCompareResult binaryCheck = knot.compare(password, sizeof(password), storedHash);

if (check && check.match) {
	login();
}
```

`compare()` returns success for a valid comparison operation even when `match` is false. It remains a synchronous convenience API.

## Cooperative compare

Use `KnotCompareOperation` when password verification must return control to FreeRTOS between bounded PBKDF2 slices.

```cpp
KnotCompareOperation operation;

KnotResult begin = knot.beginCompare(
	operation,
	"password",
	storedHash
);
if (!begin) {
	handleError(begin);
	return;
}

KnotStepResult step = operation.step(iterationBudget);
while (step.inProgress()) {
	vTaskDelay(1);
	step = operation.step(iterationBudget);
}

if (step.cancelled()) {
	handleCancellation();
} else if (!step) {
	handleError(step);
} else if (step.match) {
	login();
}
```

`iterationBudget` is the maximum number of PBKDF2 HMAC iterations performed by one `step()` call. Benchmark the target ESP32 and choose a budget that normally keeps each call near 5-20 ms.

`beginCompare()` validates the inputs and copies the password, salt, expected hash, cost, and comparison configuration into the operation. Knot's global mutex is released before the iterative HMAC work begins. The operation can therefore sleep or be scheduled through Worker without retaining the Knot lock.

The binary-safe overload is also available:

```cpp
KnotResult begin = knot.beginCompare(
	operation,
	password,
	passwordLength,
	storedHash
);
```

Cancel between steps with:

```cpp
operation.cancel();
```

A terminal `KnotStepResult` has one of these statuses:

```txt
Complete
Cancelled
Failed
```

Use `completed()`, `cancelled()`, and `inProgress()` to inspect the state. Cancellation is a successful terminal transition (`KnotCode::Ok`) with `KnotStepStatus::Cancelled`, so check `cancelled()` before treating a non-matching result as an invalid password. `iterationsCompleted` and `iterationsTotal` expose progress for diagnostics. An operation can be started again after completion, cancellation, or failure.

Do not call `step()` and `cancel()` concurrently on the same operation from different tasks. Coordinate ownership through the calling task or Worker job.

## Metadata

```cpp
KnotRoundsResult rounds = knot.getRounds(storedHash);
KnotRoundsResult cost = knot.getCost(storedHash);
KnotInfoResult info = knot.getInfo(storedHash);
```

`getRounds()` and `getCost()` return the same stored work factor.

## Rehash

```cpp
if (knot.needsRehash(storedHash, 14)) {
	KnotHashResult upgraded = knot.hash(password, 14);
}
```

Invalid hashes, unsupported algorithms, unsupported versions, invalid target costs, and lower-cost hashes return `true`. Same-cost and higher-cost hashes return `false`.

## Result codes

`KnotCode` values:

```txt
Ok
NotInitialized
AlreadyInitialized
InvalidArgument
InvalidCost
InvalidSalt
InvalidHash
PasswordTooLong
EntropyFailed
HashFailed
BufferTooSmall
UnsupportedVersion
UnsupportedAlgorithm
CryptoError
InternalError
```
