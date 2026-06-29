#include <Knot.h>
#include <internal/KnotBase64Url.h>
#include <internal/KnotCrypto.h>
#include <internal/KnotFormat.h>

#include <cstdio>
#include <cstring>

namespace {
int failureCount = 0;

void expect(bool condition, const char *message) {
	if (condition) {
		return;
	}
	std::printf("FAIL: %s\n", message);
	failureCount++;
}

void testBase64Url() {
	char encoded[64] = {};
	size_t written = 0;
	KnotResult result = zek::knot::internal::base64UrlEncode(
	    reinterpret_cast<const uint8_t *>("hello?"),
	    6,
	    encoded,
	    sizeof(encoded),
	    written
	);
	expect(result && std::strcmp(encoded, "aGVsbG8_") == 0 && written == 8, "base64url encode");

	uint8_t decoded[64] = {};
	result = zek::knot::internal::base64UrlDecode(
	    encoded,
	    written,
	    decoded,
	    sizeof(decoded),
	    written
	);
	expect(result && written == 6 && std::memcmp(decoded, "hello?", 6) == 0, "base64url decode");

	result = zek::knot::internal::base64UrlDecode("abc*", 4, decoded, sizeof(decoded), written);
	expect(!result && result.code == KnotCode::InvalidHash, "base64url invalid char");

	result = zek::knot::internal::base64UrlDecode("a", 1, decoded, sizeof(decoded), written);
	expect(!result && result.code == KnotCode::InvalidHash, "base64url invalid length");
}

void testFormat() {
	const uint8_t salt[KNOT_RAW_SALT_LENGTH] = {
	    0x00,
	    0x01,
	    0x02,
	    0x03,
	    0x04,
	    0x05,
	    0x06,
	    0x07,
	    0x08,
	    0x09,
	    0x0a,
	    0x0b,
	    0x0c,
	    0x0d,
	    0x0e,
	    0x0f,
	};
	const uint8_t hash[KNOT_RAW_HASH_LENGTH] = {
	    0x25,
	    0xeb,
	    0x86,
	    0xac,
	    0xc7,
	    0x6e,
	    0x43,
	    0x01,
	    0x8f,
	    0x18,
	    0xb9,
	    0xa8,
	    0xf9,
	    0x0c,
	    0x2f,
	    0xed,
	    0x46,
	    0x2d,
	    0x1c,
	    0x79,
	    0x9e,
	    0x83,
	    0xd4,
	    0x8a,
	    0xe3,
	    0xd7,
	    0xc6,
	    0x90,
	    0x46,
	    0xa6,
	    0x0b,
	    0x67,
	};

	char encodedSalt[KNOT_MAX_SALT_LENGTH + 1] = {};
	size_t written = 0;
	KnotResult result =
	    zek::knot::internal::encodeSalt(4, salt, encodedSalt, sizeof(encodedSalt), written);
	expect(
	    result && std::strcmp(encodedSalt, "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw") == 0,
	    "encode salt"
	);

	zek::knot::internal::KnotParsedValue parsed;
	result = zek::knot::internal::parseSalt(encodedSalt, parsed);
	expect(
	    result && parsed.cost == 4 && std::memcmp(parsed.salt, salt, sizeof(salt)) == 0 &&
	        !parsed.hasHash,
	    "parse salt"
	);

	char encodedHash[KNOT_MAX_HASH_LENGTH + 1] = {};
	result =
	    zek::knot::internal::encodeHash(4, salt, hash, encodedHash, sizeof(encodedHash), written);
	expect(
	    result &&
	        std::strcmp(
	            encodedHash,
	            "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c"
	        ) == 0,
	    "encode hash"
	);

	result = zek::knot::internal::parseHash(encodedHash, parsed);
	expect(
	    result && parsed.cost == 4 && parsed.hasHash &&
	        std::memcmp(parsed.salt, salt, sizeof(salt)) == 0 &&
	        std::memcmp(parsed.hash, hash, sizeof(hash)) == 0,
	    "parse hash"
	);

	result = zek::knot::internal::parseHash("$2b$10$not-knot", parsed);
	expect(!result && result.code == KnotCode::UnsupportedAlgorithm, "unsupported algorithm");

	result = zek::knot::internal::parseHash("$knot$v2$c4$AAECAwQFBgcICQoLDA0ODw$x", parsed);
	expect(!result && result.code == KnotCode::UnsupportedVersion, "unsupported version");
}

void testCryptoBoundary() {
	const uint8_t salt[KNOT_RAW_SALT_LENGTH] = {
	    0x00,
	    0x01,
	    0x02,
	    0x03,
	    0x04,
	    0x05,
	    0x06,
	    0x07,
	    0x08,
	    0x09,
	    0x0a,
	    0x0b,
	    0x0c,
	    0x0d,
	    0x0e,
	    0x0f,
	};
	const uint8_t expected[KNOT_RAW_HASH_LENGTH] = {
	    0x25,
	    0xeb,
	    0x86,
	    0xac,
	    0xc7,
	    0x6e,
	    0x43,
	    0x01,
	    0x8f,
	    0x18,
	    0xb9,
	    0xa8,
	    0xf9,
	    0x0c,
	    0x2f,
	    0xed,
	    0x46,
	    0x2d,
	    0x1c,
	    0x79,
	    0x9e,
	    0x83,
	    0xd4,
	    0x8a,
	    0xe3,
	    0xd7,
	    0xc6,
	    0x90,
	    0x46,
	    0xa6,
	    0x0b,
	    0x67,
	};

	uint8_t derived[KNOT_RAW_HASH_LENGTH] = {};
	KnotResult result = zek::knot::internal::pbkdf2Sha256(
	    reinterpret_cast<const uint8_t *>("password"),
	    8,
	    salt,
	    sizeof(salt),
	    zek::knot::internal::iterationsForCost(4),
	    derived,
	    sizeof(derived)
	);
	expect(result && std::memcmp(derived, expected, sizeof(expected)) == 0, "pbkdf2 vector");
	expect(
	    zek::knot::internal::constantTimeEqual(derived, expected, sizeof(expected)),
	    "constant-time equal"
	);
	derived[0] ^= 0x01;
	expect(
	    !zek::knot::internal::constantTimeEqual(derived, expected, sizeof(expected)),
	    "constant-time mismatch"
	);
	expect(
	    std::strcmp(zek::knot::internal::cryptoBackendName(), "openssl-host-test") == 0,
	    "host crypto backend"
	);
}

void testPublicApi() {
	Knot knot;
	KnotConfig config;
	config.defaultCost = 4;
	config.minCost = 4;
	config.maxCost = 6;
	KnotResult result = knot.init(config);
	expect(result && knot.initialized(), "init succeeds");

	const char *encodedSalt = "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw";
	KnotHashResult hash = knot.hash("password", encodedSalt);
	expect(
	    hash &&
	        std::strcmp(
	            hash.value,
	            "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c"
	        ) == 0,
	    "hash with encoded salt"
	);

	KnotCompareResult compare = knot.compare("password", hash.value);
	expect(compare && compare.match, "compare match");

	compare = knot.compare("wrong", hash.value);
	expect(compare && !compare.match, "compare mismatch");

	KnotRoundsResult rounds = knot.getRounds(hash.value);
	expect(rounds && rounds.value == 4, "get rounds");

	KnotInfoResult info = knot.getInfo(hash.value);
	expect(
	    info && std::strcmp(info.algorithm, "knot") == 0 && std::strcmp(info.version, "v1") == 0 &&
	        info.cost == 4,
	    "get info"
	);

	expect(!knot.needsRehash(hash.value, 4), "does not need rehash at same cost");
	expect(knot.needsRehash(hash.value, 5), "needs rehash at higher cost");
	expect(knot.needsRehash("$2b$10$not-knot", 4), "invalid hash needs rehash");

	char small[8] = {};
	result = knot.hashTo("password", encodedSalt, small, sizeof(small));
	expect(!result && result.code == KnotCode::BufferTooSmall, "hash buffer too small");

	result = knot.deinit();
	expect(result && !knot.initialized(), "deinit succeeds");
}
} // namespace

int main() {
	testBase64Url();
	testFormat();
	testCryptoBoundary();
	testPublicApi();

	if (failureCount != 0) {
		std::printf("%d host tests failed\n", failureCount);
		return 1;
	}

	std::printf("host tests passed\n");
	return 0;
}
