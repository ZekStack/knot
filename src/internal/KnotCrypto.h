#pragma once

#include "../Knot.h"

#include <cstddef>
#include <cstdint>

namespace zek::knot::internal {

struct HmacSha256Context;

uint32_t iterationsForCost(uint8_t cost);

KnotResult randomBytes(uint8_t *output, size_t outputSize);
KnotResult pbkdf2Sha256(
    const uint8_t *password,
    size_t passwordSize,
    const uint8_t *salt,
    size_t saltSize,
    uint32_t iterations,
    uint8_t *output,
    size_t outputSize
);

KnotResult hmacSha256Create(
    HmacSha256Context *&context,
    const uint8_t *key,
    size_t keySize
);
KnotResult hmacSha256Digest(
    HmacSha256Context *context,
    const uint8_t *input,
    size_t inputSize,
    uint8_t *output,
    size_t outputSize
);
void hmacSha256Destroy(HmacSha256Context *&context);

bool constantTimeEqual(const uint8_t *left, const uint8_t *right, size_t size);
void secureZero(void *data, size_t size);
const char *cryptoBackendName();

} // namespace zek::knot::internal
