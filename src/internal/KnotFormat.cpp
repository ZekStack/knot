#include "KnotFormat.h"

#include "KnotBase64Url.h"

#include <cstdio>
#include <cstring>

namespace {
constexpr const char *kPrefix = "$knot$v1$c";
constexpr size_t kPrefixLength = 10;

bool startsWith(const char *value, const char *prefix) {
	return std::strncmp(value, prefix, std::strlen(prefix)) == 0;
}

bool parseCost(const char *begin, const char *end, uint8_t &cost) {
	if (begin == nullptr || end == nullptr || begin == end) {
		return false;
	}

	unsigned value = 0;
	for (const char *cursor = begin; cursor < end; cursor++) {
		if (*cursor < '0' || *cursor > '9') {
			return false;
		}
		value = (value * 10U) + static_cast<unsigned>(*cursor - '0');
		if (value > 255U) {
			return false;
		}
	}

	cost = static_cast<uint8_t>(value);
	return true;
}

zek::knot::KnotResult parseEncoded(
    const char *input,
    bool requireHash,
    zek::knot::internal::KnotParsedValue &parsed
) {
	using namespace zek::knot;
	using namespace zek::knot::internal;

	parsed = KnotParsedValue();
	if (input == nullptr || input[0] == '\0') {
		return KnotResult::failure(
		    requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt,
		    requireHash ? "hash is required" : "salt is required"
		);
	}

	if (!startsWith(input, "$knot$")) {
		return KnotResult::failure(KnotCode::UnsupportedAlgorithm, "unsupported hash algorithm");
	}
	if (!startsWith(input, "$knot$v1$")) {
		return KnotResult::failure(KnotCode::UnsupportedVersion, "unsupported knot hash version");
	}
	if (!startsWith(input, kPrefix)) {
		return KnotResult::failure(
		    requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt,
		    "invalid knot hash format"
		);
	}

	const char *costStart = input + kPrefixLength;
	const char *costEnd = std::strchr(costStart, '$');
	if (costEnd == nullptr || !parseCost(costStart, costEnd, parsed.cost)) {
		return KnotResult::failure(
		    requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt,
		    "invalid knot cost"
		);
	}

	const char *saltStart = costEnd + 1;
	const char *saltEnd = std::strchr(saltStart, '$');
	const char *hashStart = nullptr;
	size_t saltEncodedLength = 0;
	if (saltEnd == nullptr) {
		saltEncodedLength = std::strlen(saltStart);
	} else {
		saltEncodedLength = static_cast<size_t>(saltEnd - saltStart);
		hashStart = saltEnd + 1;
	}

	if (saltEncodedLength == 0) {
		return KnotResult::failure(
		    requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt,
		    "salt is missing"
		);
	}
	if (requireHash && hashStart == nullptr) {
		return KnotResult::failure(KnotCode::InvalidHash, "hash value is missing");
	}
	if (!requireHash && hashStart != nullptr) {
		return KnotResult::failure(KnotCode::InvalidSalt, "encoded salt must not contain a hash");
	}

	size_t decoded = 0;
	KnotResult result = base64UrlDecode(
	    saltStart,
	    saltEncodedLength,
	    parsed.salt,
	    sizeof(parsed.salt),
	    decoded
	);
	if (!result) {
		result.code = requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt;
		return result;
	}
	if (decoded != KNOT_RAW_SALT_LENGTH) {
		return KnotResult::failure(
		    requireHash ? KnotCode::InvalidHash : KnotCode::InvalidSalt,
		    "salt length is invalid"
		);
	}

	if (requireHash) {
		const char *extra = std::strchr(hashStart, '$');
		if (extra != nullptr || hashStart[0] == '\0') {
			return KnotResult::failure(KnotCode::InvalidHash, "hash value is invalid");
		}

		result = base64UrlDecode(
		    hashStart,
		    std::strlen(hashStart),
		    parsed.hash,
		    sizeof(parsed.hash),
		    decoded
		);
		if (!result) {
			result.code = KnotCode::InvalidHash;
			return result;
		}
		if (decoded != KNOT_RAW_HASH_LENGTH) {
			return KnotResult::failure(KnotCode::InvalidHash, "hash length is invalid");
		}
		parsed.hasHash = true;
	}

	return KnotResult::success();
}
} // namespace

namespace zek::knot::internal {

KnotResult encodeSalt(
    uint8_t cost,
    const uint8_t *salt,
    char *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if (salt == nullptr || output == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "salt output is required");
	}

	char encodedSalt[32] = {};
	size_t saltWritten = 0;
	KnotResult result = base64UrlEncode(
	    salt,
	    KNOT_RAW_SALT_LENGTH,
	    encodedSalt,
	    sizeof(encodedSalt),
	    saltWritten
	);
	if (!result) {
		return result;
	}

	const int count = std::snprintf(output, outputSize, "$knot$v1$c%u$%s", cost, encodedSalt);
	if (count < 0) {
		return KnotResult::failure(KnotCode::InternalError, "failed to encode salt");
	}
	if (static_cast<size_t>(count) >= outputSize) {
		output[0] = '\0';
		return KnotResult::failure(KnotCode::BufferTooSmall, "salt output buffer is too small");
	}

	written = static_cast<size_t>(count);
	return KnotResult::success();
}

KnotResult encodeHash(
    uint8_t cost,
    const uint8_t *salt,
    const uint8_t *hash,
    char *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if (salt == nullptr || hash == nullptr || output == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "hash output is required");
	}

	char encodedSalt[32] = {};
	char encodedHash[64] = {};
	size_t ignored = 0;
	KnotResult result = base64UrlEncode(
	    salt,
	    KNOT_RAW_SALT_LENGTH,
	    encodedSalt,
	    sizeof(encodedSalt),
	    ignored
	);
	if (!result) {
		return result;
	}
	result = base64UrlEncode(
	    hash,
	    KNOT_RAW_HASH_LENGTH,
	    encodedHash,
	    sizeof(encodedHash),
	    ignored
	);
	if (!result) {
		return result;
	}

	const int count = std::snprintf(
	    output,
	    outputSize,
	    "$knot$v1$c%u$%s$%s",
	    cost,
	    encodedSalt,
	    encodedHash
	);
	if (count < 0) {
		return KnotResult::failure(KnotCode::InternalError, "failed to encode hash");
	}
	if (static_cast<size_t>(count) >= outputSize) {
		output[0] = '\0';
		return KnotResult::failure(KnotCode::BufferTooSmall, "hash output buffer is too small");
	}

	written = static_cast<size_t>(count);
	return KnotResult::success();
}

KnotResult parseSalt(const char *encodedSalt, KnotParsedValue &parsed) {
	return parseEncoded(encodedSalt, false, parsed);
}

KnotResult parseHash(const char *encodedHash, KnotParsedValue &parsed) {
	return parseEncoded(encodedHash, true, parsed);
}

} // namespace zek::knot::internal
