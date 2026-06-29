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

	KnotSaltResult salt = knot.genSalt(10);
	if (!salt) {
		Serial.println(salt.message);
		return;
	}

	KnotHashResult hash = knot.hash("password", salt.value);
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	Serial.println(salt.value);
	Serial.println(hash.value);
}

void loop() {
	delay(1000);
}
