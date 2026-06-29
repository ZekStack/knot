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

`compare()` returns success for a valid comparison operation even when `match` is false.

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
