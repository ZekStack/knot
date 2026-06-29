#include <Arduino.h>
#include <Knot.h>

#ifndef KNOT_BENCHMARK_COST
#define KNOT_BENCHMARK_COST 4
#endif

Knot knot;

uint32_t iterationsForCost(uint8_t cost) {
	if (cost <= KNOT_MIN_COST) {
		return 1000;
	}
	return 1000UL << (cost - KNOT_MIN_COST);
}

const char *targetName() {
#if defined(ARDUINO_BOARD)
	return ARDUINO_BOARD;
#elif defined(CONFIG_IDF_TARGET)
	return CONFIG_IDF_TARGET;
#else
	return "unknown";
#endif
}

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.defaultCost = KNOT_BENCHMARK_COST;
	KnotResult init = knot.init(config);
	if (!init) {
		Serial.println(init.message);
		return;
	}

	const uint32_t heapBefore = ESP.getFreeHeap();
	const uint32_t hashStart = millis();
	KnotHashResult hash = knot.hash("benchmark-password");
	const uint32_t hashTimeMs = millis() - hashStart;
	const uint32_t heapAfterHash = ESP.getFreeHeap();
	if (!hash) {
		Serial.println(hash.message);
		return;
	}

	const uint32_t compareStart = millis();
	KnotCompareResult compare = knot.compare("benchmark-password", hash.value);
	const uint32_t compareTimeMs = millis() - compareStart;
	const uint32_t heapAfterCompare = ESP.getFreeHeap();
	if (!compare) {
		Serial.println(compare.message);
		return;
	}

	Serial.print("Target: ");
	Serial.println(targetName());
	Serial.print("Cost: ");
	Serial.println(static_cast<unsigned>(KNOT_BENCHMARK_COST));
	Serial.print("Iterations: ");
	Serial.println(iterationsForCost(KNOT_BENCHMARK_COST));
	Serial.print("Hash time ms: ");
	Serial.println(hashTimeMs);
	Serial.print("Compare time ms: ");
	Serial.println(compareTimeMs);
	Serial.print("Free heap before: ");
	Serial.println(heapBefore);
	Serial.print("Free heap after hash: ");
	Serial.println(heapAfterHash);
	Serial.print("Free heap after compare: ");
	Serial.println(heapAfterCompare);
	Serial.print("Match: ");
	Serial.println(compare.match ? "true" : "false");
}

void loop() {
	delay(1000);
}
