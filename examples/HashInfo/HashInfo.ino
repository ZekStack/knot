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

	KnotHashResult hash = knot.hash("password", 10);
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	KnotInfoResult info = knot.getInfo(hash.value);
	if (!info) {
		Serial.println(info.message);
		return;
	}

	Serial.print("Algorithm: ");
	Serial.println(info.algorithm);
	Serial.print("Version: ");
	Serial.println(info.version);
	Serial.print("Cost: ");
	Serial.println(static_cast<unsigned>(info.cost));
}

void loop() {
	delay(1000);
}
