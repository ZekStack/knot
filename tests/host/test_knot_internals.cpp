#include <Knot.h>
#include <internal/KnotBase64Url.h>
#include <internal/KnotCrypto.h>
#include <internal/KnotFormat.h>

#include <cstddef>
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

	const char *badValues[] = {
	    "=",
	    "====",
	    "abc$",
	    "abc*",
	    "abc/",
	    "abc+",
	    "abc def",
	    "abc\n",
	};
	for (const char *badValue : badValues) {
		result = zek::knot::internal::base64UrlDecode(
		    badValue,
		    std::strlen(badValue),
		    decoded,
		    sizeof(decoded),
		    written
		);
		expect(!result, "base64url malformed fuzz case");
	}
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

	const char *badHashes[] = {
	    "",
	    "$knot$",
	    "$knot$v1$",
	    "$knot$v1$c$AAECAwQFBgcICQoLDA0ODw$x",
	    "$knot$v1$cabc$AAECAwQFBgcICQoLDA0ODw$x",
	    "$knot$v1$c256$AAECAwQFBgcICQoLDA0ODw$x",
	    "$knot$v1$c4$",
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw",
	    "$knot$v1$c4$short$x",
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$",
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$short",
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c$extra",
	};
	for (const char *badHash : badHashes) {
		result = zek::knot::internal::parseHash(badHash, parsed);
		expect(!result, "parse hash malformed fuzz case");
	}

	char oversizedSalt[160] = {};
	std::snprintf(
	    oversizedSalt,
	    sizeof(oversizedSalt),
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODwAA$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c"
	);
	result = zek::knot::internal::parseHash(oversizedSalt, parsed);
	expect(!result && result.code == KnotCode::InvalidHash, "parse hash oversized salt");

	char oversizedHash[160] = {};
	std::snprintf(
	    oversizedHash,
	    sizeof(oversizedHash),
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2cAA"
	);
	result = zek::knot::internal::parseHash(oversizedHash, parsed);
	expect(!result && result.code == KnotCode::InvalidHash, "parse hash oversized hash");
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

void testPublicApiEdgeCases() {
	const char encodedSalt[] = "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw";
	const char encodedHash[] =
	    "$knot$v1$c4$AAECAwQFBgcICQoLDA0ODw$JeuGrMduQwGPGLmo-Qwv7UYtHHmeg9SK49fGkEamC2c";

	Knot uninitialized;
	KnotHashResult hash = uninitialized.hash("password", encodedSalt);
	expect(!hash && hash.code == KnotCode::NotInitialized, "uninitialized hash");
	KnotCompareResult compare = uninitialized.compare("password", encodedHash);
	expect(!compare && compare.code == KnotCode::NotInitialized, "uninitialized compare");
	KnotSaltResult salt = uninitialized.genSalt(4);
	expect(!salt && salt.code == KnotCode::NotInitialized, "uninitialized genSalt");
	expect(uninitialized.needsRehash(encodedHash), "uninitialized needs rehash");

	Knot knot;
	KnotConfig config;
	config.defaultCost = 4;
	config.minCost = 4;
	config.maxCost = 6;
	KnotResult result = knot.init(config);
	expect(static_cast<bool>(result), "edge init succeeds");

	hash = knot.hash(static_cast<const char *>(nullptr), encodedSalt);
	expect(!hash && hash.code == KnotCode::InvalidArgument, "null c-string password");
	hash = knot.hash(static_cast<const char *>(nullptr), static_cast<uint8_t>(3));
	expect(!hash && hash.code == KnotCode::InvalidArgument, "null password before invalid cost");
	hash = knot.hash(static_cast<const char *>(nullptr), static_cast<const char *>(nullptr));
	expect(!hash && hash.code == KnotCode::InvalidArgument, "null password before null salt");
	hash = knot.hash(static_cast<const char *>(nullptr), "bad-salt");
	expect(!hash && hash.code == KnotCode::InvalidArgument, "null password before bad salt");
	hash = knot.hash(static_cast<const uint8_t *>(nullptr), 0, encodedSalt);
	expect(!hash && hash.code == KnotCode::InvalidArgument, "null empty byte password");
	char nullHashOutput[KNOT_MAX_HASH_LENGTH + 1] = {};
	nullHashOutput[0] = 'x';
	result = knot.hashTo(static_cast<const char *>(nullptr), encodedSalt, nullHashOutput, sizeof(nullHashOutput));
	expect(
	    !result && result.code == KnotCode::InvalidArgument && nullHashOutput[0] == '\0',
	    "null hashTo password clears output"
	);
	compare = knot.compare(static_cast<const char *>(nullptr), encodedHash);
	expect(!compare && compare.code == KnotCode::InvalidArgument, "null compare password");
	compare = knot.compare(static_cast<const char *>(nullptr), static_cast<const char *>(nullptr));
	expect(!compare && compare.code == KnotCode::InvalidArgument, "null password before null hash");
	compare = knot.compare(static_cast<const char *>(nullptr), "bad-hash");
	expect(!compare && compare.code == KnotCode::InvalidArgument, "null password before bad hash");
	compare = knot.compare("password", nullptr);
	expect(!compare && compare.code == KnotCode::InvalidHash, "null compare hash");

	uint8_t emptyPassword = 0;
	hash = knot.hash(&emptyPassword, 0, encodedSalt);
	expect(static_cast<bool>(hash), "empty byte password hashes");
	compare = knot.compare(&emptyPassword, 0, hash.value);
	expect(compare && compare.match, "empty byte password compares");
	hash = knot.hash("", encodedSalt);
	expect(static_cast<bool>(hash), "empty c-string password hashes");
	compare = knot.compare("", hash.value);
	expect(compare && compare.match, "empty c-string password compares");

	uint8_t binaryPassword[] = {'p', 'a', 0x00, 's', 's'};
	hash = knot.hash(binaryPassword, sizeof(binaryPassword), encodedSalt);
	expect(static_cast<bool>(hash), "binary password hashes");
	compare = knot.compare(binaryPassword, sizeof(binaryPassword), hash.value);
	expect(compare && compare.match, "binary password compares");
	compare = knot.compare("pa", hash.value);
	expect(compare && !compare.match, "binary password differs from truncated c-string");

	uint8_t maxPassword[KNOT_MAX_PASSWORD_LENGTH] = {};
	for (size_t i = 0; i < sizeof(maxPassword); i++) {
		maxPassword[i] = static_cast<uint8_t>('a' + (i % 26));
	}
	hash = knot.hash(maxPassword, sizeof(maxPassword), encodedSalt);
	expect(static_cast<bool>(hash), "max length password hashes");
	uint8_t tooLongPassword[KNOT_MAX_PASSWORD_LENGTH + 1] = {};
	hash = knot.hash(tooLongPassword, sizeof(tooLongPassword), encodedSalt);
	expect(!hash && hash.code == KnotCode::PasswordTooLong, "over max length password rejected");

	Knot shortLimit;
	KnotConfig shortLimitConfig;
	shortLimitConfig.defaultCost = 4;
	shortLimitConfig.minCost = 4;
	shortLimitConfig.maxCost = 6;
	shortLimitConfig.maxPasswordLength = 4;
	result = shortLimit.init(shortLimitConfig);
	expect(static_cast<bool>(result), "short limit init succeeds");
	char tooLongCString[5] = {'a', 'b', 'c', 'd', 'e'};
	hash = shortLimit.hash(tooLongCString, encodedSalt);
	expect(!hash && hash.code == KnotCode::PasswordTooLong, "bounded c-string hash rejects over limit");
	hash = shortLimit.hash(tooLongCString, static_cast<uint8_t>(3));
	expect(
	    !hash && hash.code == KnotCode::PasswordTooLong,
	    "bounded c-string password before invalid cost"
	);
	compare = shortLimit.compare(tooLongCString, encodedHash);
	expect(
	    !compare && compare.code == KnotCode::PasswordTooLong,
	    "bounded c-string compare rejects over limit"
	);

	char exactSalt[sizeof(encodedSalt)] = {};
	result = knot.genSaltTo(4, exactSalt, sizeof(exactSalt));
	expect(result && std::strlen(exactSalt) == std::strlen(encodedSalt), "exact salt buffer");
	char exactHash[sizeof(encodedHash)] = {};
	result = knot.hashTo("password", encodedSalt, exactHash, sizeof(exactHash));
	expect(result && std::strcmp(exactHash, encodedHash) == 0, "exact hash buffer");

	Knot noConstantTime;
	KnotConfig noConstantTimeConfig;
	noConstantTimeConfig.defaultCost = 4;
	noConstantTimeConfig.minCost = 4;
	noConstantTimeConfig.maxCost = 6;
	noConstantTimeConfig.useConstantTimeCompare = false;
	result = noConstantTime.init(noConstantTimeConfig);
	expect(static_cast<bool>(result), "non constant-time init");
	compare = noConstantTime.compare("password", encodedHash);
	expect(compare && compare.match, "non constant-time compare match");
	compare = noConstantTime.compare("wrong", encodedHash);
	expect(compare && !compare.match, "non constant-time compare mismatch");

	char salts[8][KNOT_MAX_SALT_LENGTH + 1] = {};
	bool duplicateSalt = false;
	for (size_t i = 0; i < 8; i++) {
		result = knot.genSaltTo(4, salts[i], sizeof(salts[i]));
		expect(static_cast<bool>(result), "repeated genSalt succeeds");
		for (size_t j = 0; j < i; j++) {
			if (std::strcmp(salts[i], salts[j]) == 0) {
				duplicateSalt = true;
			}
		}
	}
	expect(!duplicateSalt, "repeated genSalt uniqueness");

	expect(knot.needsRehash(encodedHash, 3), "needsRehash invalid low target cost");
	expect(knot.needsRehash(encodedHash, 7), "needsRehash invalid high target cost");
}

void testDefaultCostMigration() {
	expect(KNOT_DEFAULT_COST == 14, "default cost is 14");
	expect(zek::knot::internal::iterationsForCost(14) == 1024000UL, "cost 14 iterations");

	Knot knot;
	KnotResult result = knot.init();
	expect(static_cast<bool>(result), "default init succeeds");

	KnotSaltResult defaultSalt = knot.genSalt();
	expect(static_cast<bool>(defaultSalt), "default genSalt succeeds");
	zek::knot::internal::KnotParsedValue parsed;
	result = zek::knot::internal::parseSalt(defaultSalt.value, parsed);
	expect(result && parsed.cost == 14, "default genSalt uses cost 14");

	const char *oldSalt = "$knot$v1$c10$AAECAwQFBgcICQoLDA0ODw";
	KnotHashResult oldHash = knot.hash("password", oldSalt);
	expect(static_cast<bool>(oldHash), "old cost 10 hash can be generated");
	KnotCompareResult compare = knot.compare("password", oldHash.value);
	expect(compare && compare.match, "old cost 10 hash still verifies");
	expect(knot.needsRehash(oldHash.value), "old cost 10 hash needs default rehash");
	expect(!knot.needsRehash(oldHash.value, 10), "old cost 10 hash does not need cost 10 rehash");
}
} // namespace

int main() {
	testBase64Url();
	testFormat();
	testCryptoBoundary();
	testPublicApi();
	testPublicApiEdgeCases();
	testDefaultCostMigration();

	if (failureCount != 0) {
		std::printf("%d host tests failed\n", failureCount);
		return 1;
	}

	std::printf("host tests passed\n");
	return 0;
}
