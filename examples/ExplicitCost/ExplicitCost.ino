#include <Arduino.h>
#include <Knot.h>

Knot knot;

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.defaultCost = 4;
	KnotResult init = knot.init(config);
	if (!init) {
		Serial.println(init.message);
		return;
	}

	KnotHashResult hash = knot.hash("password", 4);
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	KnotRoundsResult rounds = knot.getRounds(hash.value);
	if (!rounds) {
		Serial.println(rounds.message);
		return;
	}

	Serial.print("Cost: ");
	Serial.println(static_cast<unsigned>(rounds.value));
}

void loop() {
	delay(1000);
}
