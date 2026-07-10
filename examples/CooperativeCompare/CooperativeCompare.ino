#include <Arduino.h>
#include <Knot.h>

Knot knot;
KnotCompareOperation compareOperation;
bool compareFinished = false;

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.defaultCost = 4; // Demo only. Use the production default after benchmarking.
	config.minCost = 4;
	config.maxCost = 16;

	KnotResult init = knot.init(config);
	if (!init) {
		Serial.println(init.message);
		compareFinished = true;
		return;
	}

	KnotHashResult hash = knot.hash("my-password");
	if (!hash) {
		Serial.println(hash.message);
		compareFinished = true;
		return;
	}

	KnotResult begin = knot.beginCompare(compareOperation, "my-password", hash.value);
	if (!begin) {
		Serial.println(begin.message);
		compareFinished = true;
	}
}

void loop() {
	if (compareFinished) {
		delay(1000);
		return;
	}

	// Benchmark on the target and choose a budget that keeps each call near 5-20 ms.
	KnotStepResult step = compareOperation.step(64);
	if (step.inProgress()) {
		// Return control to FreeRTOS between bounded PBKDF2 slices.
		delay(1);
		return;
	}

	if (!step) {
		Serial.println(step.message);
	} else {
		Serial.println(step.match ? "valid" : "invalid");
	}
	compareFinished = true;
}
