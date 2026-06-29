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
KnotHashResult hash = knot.hash("password", 12);
KnotHashResult hash = knot.hash("password", encodedSalt);
```

`hash(password)` and `hash(password, cost)` generate a fresh salt internally.

`hash(password, encodedSalt)` uses a salt produced by `genSalt()` or `genSalt(cost)`.

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
```

## Compare

```cpp
KnotCompareResult check = knot.compare("password", storedHash);

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
if (knot.needsRehash(storedHash, 12)) {
	KnotHashResult upgraded = knot.hash(password, 12);
}
```

Invalid, unsupported, old-version, or lower-cost hashes return `true`.

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
