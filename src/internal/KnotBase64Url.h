#pragma once

#include "../Knot.h"

#include <cstddef>
#include <cstdint>

namespace zek::knot::internal {

size_t base64UrlEncodedLength(size_t inputSize);
KnotResult base64UrlEncode(
    const uint8_t *input,
    size_t inputSize,
    char *output,
    size_t outputSize,
    size_t &written
);
KnotResult base64UrlDecode(
    const char *input,
    size_t inputSize,
    uint8_t *output,
    size_t outputSize,
    size_t &written
);

} // namespace zek::knot::internal
