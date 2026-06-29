#include "Knot.h"

#include "internal/KnotCrypto.h"
#include "internal/KnotFormat.h"
#include "internal/KnotMutex.h"

#include <cstring>
#include <new>

namespace zek::knot {

struct KnotImpl {
	KnotConfig config;
	bool initialized = false;
	KnotMutex mutex;
};

namespace {

KnotResult validateConfig(const KnotConfig &config) {
	if (config.minCost < KNOT_MIN_COST || config.maxCost > KNOT_MAX_COST ||
	    config.minCost > config.maxCost) {
		return KnotResult::failure(KnotCode::InvalidCost, "invalid cost range");
	}
	if (config.defaultCost < config.minCost || config.defaultCost > config.maxCost) {
		return KnotResult::failure(KnotCode::InvalidCost, "default cost is outside the configured range");
	}
	if (config.maxPasswordLength == 0 || config.maxPasswordLength > KNOT_MAX_PASSWORD_LENGTH) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid maximum password length");
	}
	return KnotResult::success();
}

KnotResult validateCost(const KnotConfig &config, uint8_t cost) {
	if (cost < config.minCost || cost > config.maxCost) {
		return KnotResult::failure(KnotCode::InvalidCost, "cost is outside the configured range");
	}
	return KnotResult::success();
}

KnotResult validatePassword(const KnotConfig &config, const uint8_t *password, size_t passwordSize) {
	if (password == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "password is required");
	}

	if (passwordSize > config.maxPasswordLength) {
		return KnotResult::failure(KnotCode::PasswordTooLong, "password is too long");
	}
	return KnotResult::success();
}

KnotResult ensureReady(const KnotImpl *impl) {
	if (impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot instance is unavailable");
	}
	if (!impl->initialized) {
		return KnotResult::failure(KnotCode::NotInitialized, "knot is not initialized");
	}
	return KnotResult::success();
}

void copyResult(KnotResult &target, const KnotResult &source) {
	target.code = source.code;
	target.message = source.message;
}

KnotResult deriveHash(
    const uint8_t *password,
    size_t passwordSize,
    uint8_t cost,
    const uint8_t *salt,
    uint8_t *hash
) {
	return internal::pbkdf2Sha256(
	    password,
	    passwordSize,
	    salt,
	    KNOT_RAW_SALT_LENGTH,
	    internal::iterationsForCost(cost),
	    hash,
	    KNOT_RAW_HASH_LENGTH
	);
}

KnotResult hashWithSalt(
    const KnotConfig &config,
    const uint8_t *password,
    size_t passwordSize,
    uint8_t cost,
    const uint8_t *salt,
    char *output,
    size_t outputSize
) {
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "hash output is required");
	}

	KnotResult result = validatePassword(config, password, passwordSize);
	if (!result) {
		output[0] = '\0';
		return result;
	}

	uint8_t derived[KNOT_RAW_HASH_LENGTH] = {};
	result = deriveHash(password, passwordSize, cost, salt, derived);
	if (!result) {
		internal::secureZero(derived, sizeof(derived));
		output[0] = '\0';
		return result;
	}

	size_t written = 0;
	result = internal::encodeHash(cost, salt, derived, output, outputSize, written);
	internal::secureZero(derived, sizeof(derived));
	return result;
}

KnotResult genSaltToLocked(KnotImpl &impl, uint8_t cost, char *output, size_t outputSize) {
	KnotResult result = ensureReady(&impl);
	if (!result) {
		return result;
	}
	result = validateCost(impl.config, cost);
	if (!result) {
		return result;
	}

	uint8_t salt[KNOT_RAW_SALT_LENGTH] = {};
	result = internal::randomBytes(salt, sizeof(salt));
	if (!result) {
		internal::secureZero(salt, sizeof(salt));
		return result;
	}

	size_t written = 0;
	result = internal::encodeSalt(cost, salt, output, outputSize, written);
	internal::secureZero(salt, sizeof(salt));
	return result;
}

KnotResult hashToCostLocked(
    KnotImpl &impl,
    const uint8_t *password,
    size_t passwordSize,
    uint8_t cost,
    char *output,
    size_t outputSize
) {
	KnotResult result = ensureReady(&impl);
	if (!result) {
		return result;
	}
	result = validateCost(impl.config, cost);
	if (!result) {
		return result;
	}

	uint8_t salt[KNOT_RAW_SALT_LENGTH] = {};
	result = internal::randomBytes(salt, sizeof(salt));
	if (!result) {
		internal::secureZero(salt, sizeof(salt));
		return result;
	}

	result = hashWithSalt(impl.config, password, passwordSize, cost, salt, output, outputSize);
	internal::secureZero(salt, sizeof(salt));
	return result;
}

KnotResult hashToSaltLocked(
    KnotImpl &impl,
    const uint8_t *password,
    size_t passwordSize,
    const char *encodedSalt,
    char *output,
    size_t outputSize
) {
	KnotResult result = ensureReady(&impl);
	if (!result) {
		return result;
	}

	internal::KnotParsedValue parsed;
	result = internal::parseSalt(encodedSalt, parsed);
	if (!result) {
		return result;
	}
	result = validateCost(impl.config, parsed.cost);
	if (!result) {
		return result;
	}

	return hashWithSalt(impl.config, password, passwordSize, parsed.cost, parsed.salt, output, outputSize);
}

KnotCompareResult compareLocked(
    KnotImpl &impl,
    const uint8_t *password,
    size_t passwordSize,
    const char *encodedHash
) {
	KnotCompareResult result;
	KnotResult base = ensureReady(&impl);
	if (!base) {
		copyResult(result, base);
		return result;
	}

	internal::KnotParsedValue parsed;
	base = internal::parseHash(encodedHash, parsed);
	if (!base) {
		copyResult(result, base);
		return result;
	}
	base = validateCost(impl.config, parsed.cost);
	if (!base) {
		copyResult(result, base);
		return result;
	}

	base = validatePassword(impl.config, password, passwordSize);
	if (!base) {
		copyResult(result, base);
		return result;
	}

	uint8_t derived[KNOT_RAW_HASH_LENGTH] = {};
	base = deriveHash(password, passwordSize, parsed.cost, parsed.salt, derived);
	if (!base) {
		copyResult(result, base);
		internal::secureZero(derived, sizeof(derived));
		return result;
	}

	result.match = impl.config.useConstantTimeCompare
	    ? internal::constantTimeEqual(derived, parsed.hash, sizeof(derived))
	    : std::memcmp(derived, parsed.hash, sizeof(derived)) == 0;
	internal::secureZero(derived, sizeof(derived));
	copyResult(result, KnotResult::success());
	return result;
}

bool needsRehashLocked(const KnotImpl &impl, const char *encodedHash, uint8_t targetCost) {
	if (!impl.initialized) {
		return true;
	}
	if (targetCost < impl.config.minCost || targetCost > impl.config.maxCost) {
		return true;
	}

	internal::KnotParsedValue parsed;
	KnotResult result = internal::parseHash(encodedHash, parsed);
	if (!result) {
		return true;
	}
	return parsed.cost < targetCost;
}

} // namespace

Knot::Knot() : _impl(new (std::nothrow) KnotImpl()) {
}

Knot::~Knot() = default;

KnotResult Knot::init(const KnotConfig &config) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}

	KnotLock lock(_impl->mutex, config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}
	if (_impl->initialized) {
		return KnotResult::failure(KnotCode::AlreadyInitialized, "knot is already initialized");
	}

	KnotResult result = validateConfig(config);
	if (!result) {
		return result;
	}

	_impl->config = config;
	_impl->initialized = true;
	return KnotResult::success();
}

KnotResult Knot::deinit() {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}
	if (!_impl->initialized) {
		return KnotResult::failure(KnotCode::NotInitialized, "knot is not initialized");
	}

	_impl->initialized = false;
	return KnotResult::success();
}

bool Knot::initialized() const {
	if (_impl == nullptr) {
		return false;
	}

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return false;
	}
	return _impl->initialized;
}

KnotSaltResult Knot::genSalt() {
	KnotSaltResult result;
	copyResult(result, genSaltTo(result.value, sizeof(result.value)));
	return result;
}

KnotSaltResult Knot::genSalt(uint8_t cost) {
	KnotSaltResult result;
	copyResult(result, genSaltTo(cost, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(const char *password) {
	KnotHashResult result;
	copyResult(result, hashTo(password, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(const char *password, uint8_t cost) {
	KnotHashResult result;
	copyResult(result, hashTo(password, cost, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(const char *password, const char *encodedSalt) {
	KnotHashResult result;
	copyResult(result, hashTo(password, encodedSalt, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(const uint8_t *password, size_t passwordLen) {
	KnotHashResult result;
	copyResult(result, hashTo(password, passwordLen, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(const uint8_t *password, size_t passwordLen, uint8_t cost) {
	KnotHashResult result;
	copyResult(result, hashTo(password, passwordLen, cost, result.value, sizeof(result.value)));
	return result;
}

KnotHashResult Knot::hash(
    const uint8_t *password,
    size_t passwordLen,
    const char *encodedSalt
) {
	KnotHashResult result;
	copyResult(result, hashTo(password, passwordLen, encodedSalt, result.value, sizeof(result.value)));
	return result;
}

KnotResult Knot::genSaltTo(char *output, size_t outputSize) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "salt output is required");
	}
	output[0] = '\0';

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}

	return genSaltToLocked(*_impl, _impl->config.defaultCost, output, outputSize);
}

KnotResult Knot::genSaltTo(uint8_t cost, char *output, size_t outputSize) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "salt output is required");
	}
	output[0] = '\0';

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}

	return genSaltToLocked(*_impl, cost, output, outputSize);
}

KnotResult Knot::hashTo(const char *password, char *output, size_t outputSize) {
	const size_t passwordSize = password == nullptr ? 0 : std::strlen(password);
	return hashTo(reinterpret_cast<const uint8_t *>(password), passwordSize, output, outputSize);
}

KnotResult Knot::hashTo(const char *password, uint8_t cost, char *output, size_t outputSize) {
	const size_t passwordSize = password == nullptr ? 0 : std::strlen(password);
	return hashTo(reinterpret_cast<const uint8_t *>(password), passwordSize, cost, output, outputSize);
}

KnotResult Knot::hashTo(
    const char *password,
    const char *encodedSalt,
    char *output,
    size_t outputSize
) {
	const size_t passwordSize = password == nullptr ? 0 : std::strlen(password);
	return hashTo(
	    reinterpret_cast<const uint8_t *>(password),
	    passwordSize,
	    encodedSalt,
	    output,
	    outputSize
	);
}

KnotResult Knot::hashTo(
    const uint8_t *password,
    size_t passwordLen,
    char *output,
    size_t outputSize
) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "hash output is required");
	}
	output[0] = '\0';

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}

	return hashToCostLocked(*_impl, password, passwordLen, _impl->config.defaultCost, output, outputSize);
}

KnotResult Knot::hashTo(
    const uint8_t *password,
    size_t passwordLen,
    uint8_t cost,
    char *output,
    size_t outputSize
) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "hash output is required");
	}
	output[0] = '\0';

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}

	return hashToCostLocked(*_impl, password, passwordLen, cost, output, outputSize);
}

KnotResult Knot::hashTo(
    const uint8_t *password,
    size_t passwordLen,
    const char *encodedSalt,
    char *output,
    size_t outputSize
) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "hash output is required");
	}
	output[0] = '\0';

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
	}

	return hashToSaltLocked(*_impl, password, passwordLen, encodedSalt, output, outputSize);
}

KnotCompareResult Knot::compare(const char *password, const char *encodedHash) {
	const size_t passwordSize = password == nullptr ? 0 : std::strlen(password);
	return compare(reinterpret_cast<const uint8_t *>(password), passwordSize, encodedHash);
}

KnotCompareResult Knot::compare(
    const uint8_t *password,
    size_t passwordLen,
    const char *encodedHash
) {
	KnotCompareResult result;
	if (_impl == nullptr) {
		copyResult(result, KnotResult::failure(KnotCode::InternalError, "knot allocation failed"));
		return result;
	}

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		copyResult(result, KnotResult::failure(KnotCode::InternalError, "failed to lock knot"));
		return result;
	}

	return compareLocked(*_impl, password, passwordLen, encodedHash);
}

KnotRoundsResult Knot::getRounds(const char *encodedHash) {
	return getCost(encodedHash);
}

KnotRoundsResult Knot::getCost(const char *encodedHash) {
	KnotRoundsResult result;
	internal::KnotParsedValue parsed;
	KnotResult base = internal::parseHash(encodedHash, parsed);
	if (!base) {
		copyResult(result, base);
		return result;
	}
	result.value = parsed.cost;
	copyResult(result, KnotResult::success());
	return result;
}

KnotInfoResult Knot::getInfo(const char *encodedHash) {
	KnotInfoResult result;
	internal::KnotParsedValue parsed;
	KnotResult base = internal::parseHash(encodedHash, parsed);
	if (!base) {
		copyResult(result, base);
		return result;
	}

	std::strncpy(result.algorithm, "knot", sizeof(result.algorithm) - 1);
	std::strncpy(result.version, "v1", sizeof(result.version) - 1);
	result.cost = parsed.cost;
	copyResult(result, KnotResult::success());
	return result;
}

bool Knot::needsRehash(const char *encodedHash) const {
	if (_impl == nullptr) {
		return true;
	}

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return true;
	}
	return needsRehashLocked(*_impl, encodedHash, _impl->config.defaultCost);
}

bool Knot::needsRehash(const char *encodedHash, uint8_t targetCost) const {
	if (_impl == nullptr) {
		return true;
	}

	KnotLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return true;
	}
	return needsRehashLocked(*_impl, encodedHash, targetCost);
}

const char *Knot::codeToString(KnotCode code) const {
	switch (code) {
	case KnotCode::Ok:
		return "Ok";
	case KnotCode::NotInitialized:
		return "NotInitialized";
	case KnotCode::AlreadyInitialized:
		return "AlreadyInitialized";
	case KnotCode::InvalidArgument:
		return "InvalidArgument";
	case KnotCode::InvalidCost:
		return "InvalidCost";
	case KnotCode::InvalidSalt:
		return "InvalidSalt";
	case KnotCode::InvalidHash:
		return "InvalidHash";
	case KnotCode::PasswordTooLong:
		return "PasswordTooLong";
	case KnotCode::EntropyFailed:
		return "EntropyFailed";
	case KnotCode::HashFailed:
		return "HashFailed";
	case KnotCode::BufferTooSmall:
		return "BufferTooSmall";
	case KnotCode::UnsupportedVersion:
		return "UnsupportedVersion";
	case KnotCode::UnsupportedAlgorithm:
		return "UnsupportedAlgorithm";
	case KnotCode::CryptoError:
		return "CryptoError";
	case KnotCode::InternalError:
		return "InternalError";
	}
	return "Unknown";
}

const char *Knot::cryptoBackendName() const {
	return internal::cryptoBackendName();
}

} // namespace zek::knot
