#include <Arduino.h>
#include <Knot.h>

Knot knot;

void setup() {
	Serial.begin(115200);

	KnotConfig config;
	config.memory.allocation = Strata::Placement::PreferExternal;

	KnotResult result = knot.init(config);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	KnotDiagnostics diagnostics = knot.getDiagnostics();
	Serial.printf(
	    "allocation=%u implementationRegion=%u mutexRegion=%u\n",
	    static_cast<unsigned>(diagnostics.allocationPlacement),
	    static_cast<unsigned>(diagnostics.implementationRegion),
	    static_cast<unsigned>(diagnostics.mutexControlRegion)
	);

	KnotCompareOperation operation;
	KnotCompareOperationDiagnostics before = operation.getDiagnostics();
	Serial.printf("operationAllocatedBeforeBegin=%s\n", before.storageAllocated ? "yes" : "no");
}

void loop() {
	delay(1000);
}
