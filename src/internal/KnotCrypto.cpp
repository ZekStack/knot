#include "KnotCrypto.h"

namespace zek::knot::internal {

uint32_t iterationsForCost(uint8_t cost) {
	if (cost <= KNOT_MIN_COST) {
		return 1000;
	}
	return 1000UL << (cost - KNOT_MIN_COST);
}

bool constantTimeEqual(const uint8_t *left, const uint8_t *right, size_t size) {
	if (left == nullptr || right == nullptr) {
		return false;
	}

	uint8_t diff = 0;
	for (size_t i = 0; i < size; i++) {
		diff |= static_cast<uint8_t>(left[i] ^ right[i]);
	}
	return diff == 0;
}

void secureZero(void *data, size_t size) {
	if (data == nullptr) {
		return;
	}

	volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
	while (size-- > 0) {
		*cursor++ = 0;
	}
}

} // namespace zek::knot::internal
