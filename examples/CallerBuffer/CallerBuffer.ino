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

	char salt[KNOT_MAX_SALT_LENGTH + 1] = {};
	KnotResult result = knot.genSaltTo(10, salt, sizeof(salt));
	if (!result) {
		Serial.println(result.message);
		return;
	}

	char hash[KNOT_MAX_HASH_LENGTH + 1] = {};
	result = knot.hashTo("password", salt, hash, sizeof(hash));
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(hash);
}

void loop() {
	delay(1000);
}
