#include <Arduino.h>
#include <Knot.h>

Knot knot;

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.defaultCost = 9;
	config.minCost = 4;
	config.maxCost = 12;
	config.maxPasswordLength = 48;
	config.useMutex = true;
	config.useConstantTimeCompare = true;

	KnotResult init = knot.init(config);
	if (!init) {
		Serial.println(init.message);
		return;
	}

	KnotHashResult hash = knot.hash("short-password");
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	Serial.println(hash.value);
}

void loop() {
	delay(1000);
}
