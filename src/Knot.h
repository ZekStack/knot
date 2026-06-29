#pragma once

#include <Arduino.h>
#include <cstddef>
#include <cstdint>
#include <memory>

#define KNOT_DEFAULT_COST 10
#define KNOT_MIN_COST 4
#define KNOT_MAX_COST 16
#define KNOT_MAX_PASSWORD_LENGTH 72
#define KNOT_RAW_SALT_LENGTH 16
#define KNOT_RAW_HASH_LENGTH 32
#define KNOT_MAX_SALT_LENGTH 96
#define KNOT_MAX_HASH_LENGTH 192

namespace zek::knot {

struct KnotImpl;

enum class KnotCode : uint8_t {
	Ok,
	NotInitialized,
	AlreadyInitialized,
	InvalidArgument,
	InvalidCost,
	InvalidSalt,
	InvalidHash,
	PasswordTooLong,
	EntropyFailed,
	HashFailed,
	BufferTooSmall,
	UnsupportedVersion,
	UnsupportedAlgorithm,
	CryptoError,
	InternalError,
};

struct KnotResult {
	KnotCode code = KnotCode::Ok;
	const char *message = "ok";

	explicit operator bool() const {
		return code == KnotCode::Ok;
	}

	static KnotResult success(const char *message = "ok") {
		KnotResult result;
		result.code = KnotCode::Ok;
		result.message = message;
		return result;
	}

	static KnotResult failure(KnotCode code, const char *message) {
		KnotResult result;
		result.code = code;
		result.message = message;
		return result;
	}
};

struct KnotConfig {
	uint8_t defaultCost = KNOT_DEFAULT_COST;
	uint8_t minCost = KNOT_MIN_COST;
	uint8_t maxCost = KNOT_MAX_COST;
	size_t maxPasswordLength = KNOT_MAX_PASSWORD_LENGTH;
	bool useMutex = true;
	bool useConstantTimeCompare = true;
};

struct KnotSaltResult : KnotResult {
	char value[KNOT_MAX_SALT_LENGTH + 1] = {};
};

struct KnotHashResult : KnotResult {
	char value[KNOT_MAX_HASH_LENGTH + 1] = {};
};

struct KnotCompareResult : KnotResult {
	bool match = false;
};

struct KnotRoundsResult : KnotResult {
	uint8_t value = 0;
};

struct KnotInfoResult : KnotResult {
	char algorithm[16] = {};
	char version[8] = {};
	uint8_t cost = 0;
};

class Knot {
  public:
	Knot();
	~Knot();

	Knot(const Knot &) = delete;
	Knot &operator=(const Knot &) = delete;

	KnotResult init(const KnotConfig &config = KnotConfig());
	KnotResult deinit();
	bool initialized() const;

	KnotSaltResult genSalt();
	KnotSaltResult genSalt(uint8_t cost);

	KnotHashResult hash(const char *password);
	KnotHashResult hash(const char *password, uint8_t cost);
	KnotHashResult hash(const char *password, const char *encodedSalt);

	KnotResult genSaltTo(char *output, size_t outputSize);
	KnotResult genSaltTo(uint8_t cost, char *output, size_t outputSize);

	KnotResult hashTo(const char *password, char *output, size_t outputSize);
	KnotResult hashTo(const char *password, uint8_t cost, char *output, size_t outputSize);
	KnotResult hashTo(
	    const char *password,
	    const char *encodedSalt,
	    char *output,
	    size_t outputSize
	);

	KnotCompareResult compare(const char *password, const char *encodedHash);

	KnotRoundsResult getRounds(const char *encodedHash);
	KnotRoundsResult getCost(const char *encodedHash);
	KnotInfoResult getInfo(const char *encodedHash);

	bool needsRehash(const char *encodedHash) const;
	bool needsRehash(const char *encodedHash, uint8_t targetCost) const;

	const char *codeToString(KnotCode code) const;
	const char *cryptoBackendName() const;

  private:
	std::unique_ptr<KnotImpl> _impl;
};

} // namespace zek::knot

#ifndef ZEK_KNOT_DISABLE_GLOBAL_ALIASES
using Knot = zek::knot::Knot;
using KnotCode = zek::knot::KnotCode;
using KnotCompareResult = zek::knot::KnotCompareResult;
using KnotConfig = zek::knot::KnotConfig;
using KnotHashResult = zek::knot::KnotHashResult;
using KnotInfoResult = zek::knot::KnotInfoResult;
using KnotResult = zek::knot::KnotResult;
using KnotRoundsResult = zek::knot::KnotRoundsResult;
using KnotSaltResult = zek::knot::KnotSaltResult;
#endif
