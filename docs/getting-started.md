# Getting Started

Knot hashes passwords into self-contained strings that can be stored directly in a database, config file, or remote account record.

## Basic flow

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

	KnotHashResult hash = knot.hash("password");
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	savePasswordHash(hash.value);
}
```

Later, verify an input password against the stored hash:

```cpp
KnotCompareResult check = knot.compare(inputPassword, storedHash);
if (!check) {
	Serial.println(check.message);
	return;
}

if (check.match) {
	login();
} else {
	rejectLogin();
}
```

## Encoded format

Knot v0.1 writes hashes like this:

```txt
$knot$v1$c10$<base64url-salt>$<base64url-derived-key>
```

The hash contains the algorithm marker, version, cost, salt, and derived key. Do not store salts separately.
