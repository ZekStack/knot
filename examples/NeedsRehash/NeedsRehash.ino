#include <Arduino.h>
#include <Knot.h>

#include <cstring>

Knot knot;
char storedHash[KNOT_MAX_HASH_LENGTH + 1] = {};

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.defaultCost = 4;

	KnotResult init = knot.init(config);
	if (!init) {
		Serial.println(init.message);
		return;
	}

	KnotHashResult initial = knot.hash("password", 4);
	if (!initial) {
		Serial.println(initial.message);
		return;
	}
	strncpy(storedHash, initial.value, sizeof(storedHash) - 1);

	KnotCompareResult check = knot.compare("password", storedHash);
	if (!check || !check.match) {
		Serial.println(check ? "password mismatch" : check.message);
		return;
	}

	if (knot.needsRehash(storedHash)) {
		KnotHashResult upgraded = knot.hash("password");
		if (upgraded) {
			strncpy(storedHash, upgraded.value, sizeof(storedHash) - 1);
			Serial.println("hash upgraded");
		}
	} else {
		Serial.println("hash is current");
	}
}

void loop() {
	delay(1000);
}
