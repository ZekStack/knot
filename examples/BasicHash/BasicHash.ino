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

	Serial.print("Stored hash: ");
	Serial.println(hash.value);

	KnotCompareResult check = knot.compare("my-password", hash.value);
	if (!check) {
		Serial.println(check.message);
		return;
	}

	Serial.println(check.match ? "Password is valid" : "Password is invalid");
}

void loop() {
	delay(1000);
}
