#include "KnotBase64Url.h"

namespace {
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int decodeChar(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '-') {
		return 62;
	}
	if (c == '_') {
		return 63;
	}
	return -1;
}
} // namespace

namespace zek::knot::internal {

size_t base64UrlEncodedLength(size_t inputSize) {
	const size_t padded = ((inputSize + 2) / 3) * 4;
	const size_t remainder = inputSize % 3;
	if (remainder == 0) {
		return padded;
	}
	return padded - (3 - remainder);
}

KnotResult base64UrlEncode(
    const uint8_t *input,
    size_t inputSize,
    char *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if ((input == nullptr && inputSize > 0) || output == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid base64url input");
	}

	const size_t required = base64UrlEncodedLength(inputSize);
	if (outputSize <= required) {
		return KnotResult::failure(KnotCode::BufferTooSmall, "base64url output buffer is too small");
	}

	size_t out = 0;
	for (size_t i = 0; i < inputSize; i += 3) {
		const uint32_t b0 = input[i];
		const bool hasB1 = i + 1 < inputSize;
		const bool hasB2 = i + 2 < inputSize;
		const uint32_t b1 = hasB1 ? input[i + 1] : 0;
		const uint32_t b2 = hasB2 ? input[i + 2] : 0;
		const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

		output[out++] = kAlphabet[(triple >> 18) & 0x3F];
		output[out++] = kAlphabet[(triple >> 12) & 0x3F];
		if (hasB1) {
			output[out++] = kAlphabet[(triple >> 6) & 0x3F];
		}
		if (hasB2) {
			output[out++] = kAlphabet[triple & 0x3F];
		}
	}

	output[out] = '\0';
	written = out;
	return KnotResult::success();
}

KnotResult base64UrlDecode(
    const char *input,
    size_t inputSize,
    uint8_t *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if ((input == nullptr && inputSize > 0) || output == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid base64url input");
	}
	if ((inputSize % 4) == 1) {
		return KnotResult::failure(KnotCode::InvalidHash, "invalid base64url length");
	}

	uint32_t buffer = 0;
	int bits = -8;
	size_t out = 0;
	for (size_t i = 0; i < inputSize; i++) {
		const int value = decodeChar(input[i]);
		if (value < 0) {
			return KnotResult::failure(KnotCode::InvalidHash, "invalid base64url character");
		}

		buffer = (buffer << 6) | static_cast<uint32_t>(value);
		bits += 6;
		if (bits >= 0) {
			if (out >= outputSize) {
				return KnotResult::failure(KnotCode::BufferTooSmall, "base64url output buffer is too small");
			}
			output[out++] = static_cast<uint8_t>((buffer >> bits) & 0xFF);
			bits -= 8;
		}
	}

	written = out;
	return KnotResult::success();
}

} // namespace zek::knot::internal
