#include <Knot.h>

#include <cstdio>

namespace {
int failures = 0;

void expect(bool value, const char *message) {
	if (!value) {
		std::printf("FAIL: %s\n", message);
		failures++;
	}
}

const char *knownHash =
    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c";

KnotConfig baseConfig() {
	KnotConfig config;
	config.defaultCost = 4;
	config.minCost = 4;
	config.maxCost = 6;
	return config;
}

KnotStepResult finish(KnotCompareOperation &operation) {
	KnotStepResult step = operation.step(64);
	while (step.inProgress()) {
		step = operation.step(64);
	}
	return step;
}
} // namespace

int main() {
	KnotCompareOperation operation;
	auto operationDiag = operation.getDiagnostics();
	expect(!operationDiag.storageAllocated, "operation storage is lazy");
	expect(!operationDiag.active, "fresh operation is inactive");
	KnotStepResult idle = operation.step(1);
	expect(!idle && idle.code == KnotCode::NotInitialized, "step before begin stays NotInitialized");

	Knot first;
	KnotConfig internal = baseConfig();
	internal.memory.allocation = Strata::Placement::Internal;
	expect(static_cast<bool>(first.init(internal)), "internal policy init");

	KnotDiagnostics firstDiag = first.getDiagnostics();
	expect(firstDiag.initialized, "diagnostics report initialized");
	expect(firstDiag.mutexEnabled, "diagnostics report mutex enabled");
	expect(
	    firstDiag.allocationPlacement == Strata::Placement::Internal,
	    "diagnostics report allocation policy"
	);

	KnotResult begin = first.beginCompare(operation, "password", knownHash);
	expect(static_cast<bool>(begin), "begin compare under internal policy");
	operationDiag = operation.getDiagnostics();
	expect(operationDiag.storageAllocated, "operation storage allocated on begin");
	expect(operationDiag.active, "operation diagnostics report active");
	expect(
	    operationDiag.requestedPlacement == Strata::Placement::Internal,
	    "operation inherits internal placement"
	);

	expect(static_cast<bool>(first.deinit()), "deinit while operation active");
	KnotStepResult completed = finish(operation);
	expect(completed.completed() && completed.match, "active operation survives Knot deinit");

	Knot second;
	KnotConfig normal = baseConfig();
	normal.memory.allocation = Strata::Placement::Default;
	expect(static_cast<bool>(second.init(normal)), "default policy init");
	begin = second.beginCompare(operation, "password", knownHash);
	expect(static_cast<bool>(begin), "reused operation begins under new policy");
	operationDiag = operation.getDiagnostics();
	expect(
	    operationDiag.requestedPlacement == Strata::Placement::Default,
	    "operation is re-homed when policy changes"
	);
	expect(static_cast<bool>(operation.cancel()), "re-homed operation cancels");

	Knot requiredExternal;
	KnotConfig strict = baseConfig();
	strict.memory.allocation = Strata::Placement::RequireExternal;
	KnotResult strictResult = requiredExternal.init(strict);
	expect(
	    !strictResult && strictResult.code == KnotCode::AllocationFailed,
	    "unsupported required external policy fails deterministically"
	);

	Knot invalid;
	KnotConfig invalidConfig = baseConfig();
	invalidConfig.memory.allocation = static_cast<Strata::Placement>(0xff);
	KnotResult invalidResult = invalid.init(invalidConfig);
	expect(
	    !invalidResult && invalidResult.code == KnotCode::InvalidArgument,
	    "invalid memory policy is rejected"
	);

	Knot unusedTaskPolicy;
	KnotConfig taskPolicy = baseConfig();
	taskPolicy.memory.taskStack = Strata::Placement::RequireExternal;
	expect(
	    static_cast<bool>(unusedTaskPolicy.init(taskPolicy)),
	    "unused task stack policy does not impose an external-memory requirement"
	);

	if (failures != 0) {
		std::printf("%d memory tests failed\n", failures);
		return 1;
	}
	std::printf("memory tests passed\n");
	return 0;
}
