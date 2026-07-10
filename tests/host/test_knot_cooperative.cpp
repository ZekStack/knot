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

const char *knownSalt = "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw";
const char *knownHash =
    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c";

KnotStepResult run(KnotCompareOperation &operation, uint32_t budget, int &steps) {
	KnotStepResult result = operation.step(budget);
	steps = 1;
	uint32_t previous = 0;
	while (result.inProgress()) {
		expect(result.iterationsCompleted > previous, "step makes progress");
		expect(result.iterationsCompleted - previous <= budget, "step respects budget");
		previous = result.iterationsCompleted;
		result = operation.step(budget);
		steps++;
	}
	return result;
}
} // namespace

int main() {
	Knot knot;
	KnotConfig config;
	config.defaultCost = 4;
	config.minCost = 4;
	config.maxCost = 6;
	expect(static_cast<bool>(knot.init(config)), "init");

	KnotCompareOperation operation;
	KnotResult begin = knot.beginCompare(operation, "password", knownHash);
	expect(static_cast<bool>(begin), "begin match");
	expect(operation.active(), "operation active after begin");

	KnotResult secondBegin = knot.beginCompare(operation, "password", knownHash);
	expect(
	    !secondBegin && secondBegin.code == KnotCode::AlreadyInitialized,
	    "active operation cannot restart"
	);

	int steps = 0;
	KnotStepResult result = run(operation, 17, steps);
	expect(result.completed() && result.match, "cooperative match");
	expect(
	    result.iterationsCompleted == 1000 && result.iterationsTotal == 1000,
	    "iteration totals"
	);
	expect(steps > 1, "cooperative compare uses multiple steps");
	expect(!operation.active(), "operation inactive after completion");

	begin = knot.beginCompare(operation, "wrong", knownHash);
	expect(static_cast<bool>(begin), "begin mismatch");
	result = run(operation, 31, steps);
	expect(result.completed() && !result.match, "cooperative mismatch");

	begin = knot.beginCompare(operation, "password", knownHash);
	expect(static_cast<bool>(begin), "begin cancellation");
	result = operation.step(9);
	expect(result.inProgress() && result.iterationsCompleted == 9, "partial step before cancel");
	expect(static_cast<bool>(operation.cancel()), "cancel succeeds");
	result = operation.step(9);
	expect(result.cancelled() && result.code == KnotCode::Ok, "cancelled terminal result");
	expect(!operation.active(), "operation inactive after cancel");

	begin = knot.beginCompare(operation, "password", knownHash);
	expect(static_cast<bool>(begin), "operation reusable after cancel");
	expect(static_cast<bool>(knot.deinit()), "deinit while operation active");
	result = run(operation, 23, steps);
	expect(result.completed() && result.match, "operation independent after begin");

	KnotCompareOperation invalid;
	KnotStepResult idle = invalid.step(1);
	expect(!idle && idle.code == KnotCode::NotInitialized, "step before begin");

	Knot knot2;
	expect(static_cast<bool>(knot2.init(config)), "second init");
	begin = knot2.beginCompare(invalid, "password", "bad-hash");
	expect(!begin && !invalid.active(), "invalid hash begin fails cleanly");

	uint8_t binaryPassword[] = {'p', 'a', 0x00, 's', 's'};
	KnotHashResult binaryHash = knot2.hash(binaryPassword, sizeof(binaryPassword), knownSalt);
	expect(static_cast<bool>(binaryHash), "binary password hash");
	KnotCompareOperation binaryOperation;
	begin = knot2.beginCompare(
	    binaryOperation,
	    binaryPassword,
	    sizeof(binaryPassword),
	    binaryHash.value
	);
	expect(static_cast<bool>(begin), "binary begin");
	result = run(binaryOperation, 19, steps);
	expect(result.completed() && result.match, "binary cooperative match");
	begin = knot2.beginCompare(binaryOperation, "pa", binaryHash.value);
	expect(static_cast<bool>(begin), "truncated binary begin");
	result = run(binaryOperation, 19, steps);
	expect(result.completed() && !result.match, "binary differs from truncated string");

	KnotCompareOperation zeroBudget;
	begin = knot2.beginCompare(zeroBudget, "password", knownHash);
	expect(static_cast<bool>(begin), "begin zero budget");
	result = zeroBudget.step(0);
	expect(
	    !result && result.status == KnotStepStatus::Failed && !zeroBudget.active(),
	    "zero budget is terminal error"
	);

	KnotCompareResult synchronous = knot2.compare("password", knownHash);
	expect(synchronous && synchronous.match, "synchronous compare preserved");

	if (failures != 0) {
		std::printf("%d cooperative tests failed\n", failures);
		return 1;
	}
	std::printf("cooperative tests passed\n");
	return 0;
}
