#pragma once

#include "../Knot.h"

#include <cstddef>
#include <cstdint>

namespace zek::knot::internal {

struct KnotParsedValue {
	uint8_t cost = 0;
	uint8_t salt[KNOT_RAW_SALT_LENGTH] = {};
	uint8_t hash[KNOT_RAW_HASH_LENGTH] = {};
	bool hasHash = false;
};

KnotResult encodeSalt(
    uint8_t cost,
    const uint8_t *salt,
    char *output,
    size_t outputSize,
    size_t &written
);
KnotResult encodeHash(
    uint8_t cost,
    const uint8_t *salt,
    const uint8_t *hash,
    char *output,
    size_t outputSize,
    size_t &written
);
KnotResult parseSalt(const char *encodedSalt, KnotParsedValue &parsed);
KnotResult parseHash(const char *encodedHash, KnotParsedValue &parsed);

} // namespace zek::knot::internal
