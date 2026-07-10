#include "Knot.h"

#include "internal/KnotCrypto.h"
#include "internal/KnotFormat.h"
#include "internal/KnotMutex.h"

#include <cstring>
#include <new>

namespace zek::knot {

// Keep this definition identical to the private implementation in Knot.cpp.
struct KnotImpl {
	KnotConfig config;
	bool initialized = false;
	KnotMutex mutex;
};

struct KnotCompareOperationImpl {
	internal::HmacSha256Context *hmac = nullptr;
	uint8_t password[KNOT_MAX_PASSWORD_LENGTH] = {};
	size_t passwordSize = 0;
	uint8_t salt[KNOT_RAW_SALT_LENGTH] = {};
	uint8_t expectedHash[KNOT_RAW_HASH_LENGTH] = {};
	uint8_t u[KNOT_RAW_HASH_LENGTH] = {};
	uint8_t accumulated[KNOT_RAW_HASH_LENGTH] = {};
	uint8_t derivedKeyBlock[KNOT_RAW_HASH_LENGTH] = {};
	uint32_t currentIteration = 0;
	uint32_t totalIterations = 0;
	uint32_t completedIterations = 0;
	uint32_t totalIterationsSnapshot = 0;
	bool useConstantTimeCompare = true;
	bool terminalMatch = false;
	KnotStepStatus status = KnotStepStatus::Idle;
	KnotCode terminalCode = KnotCode::Ok;
	const char *terminalMessage = "ok";
};

namespace {

KnotResult validatePassword(const KnotConfig &config, const uint8_t *password, size_t passwordSize) {
	if (password == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "password is required");
	}
	if (passwordSize > config.maxPasswordLength) {
		return KnotResult::failure(KnotCode::PasswordTooLong, "password is too long");
	}
	return KnotResult::success();
}

KnotResult validateCost(const KnotConfig &config, uint8_t cost) {
	if (cost < config.minCost || cost > config.maxCost) {
		return KnotResult::failure(KnotCode::InvalidCost, "cost is outside the configured range");
	}
	return KnotResult::success();
}

KnotResult boundedCStringLength(const char *password, size_t maxLen, size_t &length) {
	length = 0;
	if (password == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "password is required");
	}
	while (length <= maxLen) {
		if (password[length] == '\0') {
			return KnotResult::success();
		}
		length++;
	}
	return KnotResult::failure(KnotCode::PasswordTooLong, "password is too long");
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

void clearSecrets(KnotCompareOperationImpl &impl) {
	internal::hmacSha256Destroy(impl.hmac);
	internal::secureZero(impl.password, sizeof(impl.password));
	internal::secureZero(impl.salt, sizeof(impl.salt));
	internal::secureZero(impl.expectedHash, sizeof(impl.expectedHash));
	internal::secureZero(impl.u, sizeof(impl.u));
	internal::secureZero(impl.accumulated, sizeof(impl.accumulated));
	internal::secureZero(impl.derivedKeyBlock, sizeof(impl.derivedKeyBlock));
	impl.passwordSize = 0;
	impl.currentIteration = 0;
	impl.totalIterations = 0;
	impl.useConstantTimeCompare = true;
}

void resetOperation(KnotCompareOperationImpl &impl) {
	clearSecrets(impl);
	impl.completedIterations = 0;
	impl.totalIterationsSnapshot = 0;
	impl.terminalMatch = false;
	impl.status = KnotStepStatus::Idle;
	impl.terminalCode = KnotCode::Ok;
	impl.terminalMessage = "ok";
}

KnotStepResult makeStepResult(const KnotCompareOperationImpl &impl) {
	KnotStepResult result;
	result.code = impl.terminalCode;
	result.message = impl.terminalMessage;
	result.status = impl.status;
	result.match = impl.terminalMatch;
	result.iterationsCompleted = impl.completedIterations;
	result.iterationsTotal = impl.totalIterationsSnapshot;
	return result;
}

KnotStepResult failOperation(KnotCompareOperationImpl &impl, KnotCode code, const char *message) {
	const uint32_t completed = impl.currentIteration;
	const uint32_t total = impl.totalIterationsSnapshot;
	clearSecrets(impl);
	impl.completedIterations = completed;
	impl.totalIterationsSnapshot = total;
	impl.terminalMatch = false;
	impl.status = KnotStepStatus::Failed;
	impl.terminalCode = code;
	impl.terminalMessage = message;
	return makeStepResult(impl);
}

KnotResult prepareLocked(
    KnotImpl &knot,
    KnotCompareOperationImpl &operation,
    const uint8_t *password,
    size_t passwordSize,
    const char *encodedHash
) {
	KnotResult result = ensureReady(&knot);
	if (!result) {
		return result;
	}
	result = validatePassword(knot.config, password, passwordSize);
	if (!result) {
		return result;
	}

	internal::KnotParsedValue parsed;
	result = internal::parseHash(encodedHash, parsed);
	if (!result) {
		internal::secureZero(&parsed, sizeof(parsed));
		return result;
	}
	result = validateCost(knot.config, parsed.cost);
	if (!result) {
		internal::secureZero(&parsed, sizeof(parsed));
		return result;
	}

	if (passwordSize != 0) {
		std::memcpy(operation.password, password, passwordSize);
	}
	operation.passwordSize = passwordSize;
	std::memcpy(operation.salt, parsed.salt, sizeof(operation.salt));
	std::memcpy(operation.expectedHash, parsed.hash, sizeof(operation.expectedHash));
	operation.totalIterations = internal::iterationsForCost(parsed.cost);
	operation.totalIterationsSnapshot = operation.totalIterations;
	operation.useConstantTimeCompare = knot.config.useConstantTimeCompare;
	internal::secureZero(&parsed, sizeof(parsed));
	return KnotResult::success();
}

KnotResult initializeHmac(KnotCompareOperationImpl &operation) {
	KnotResult result = internal::hmacSha256Create(
	    operation.hmac,
	    operation.password,
	    operation.passwordSize
	);
	if (!result) {
		const uint32_t total = operation.totalIterationsSnapshot;
		clearSecrets(operation);
		operation.totalIterationsSnapshot = total;
		operation.status = KnotStepStatus::Failed;
		operation.terminalCode = result.code;
		operation.terminalMessage = result.message;
		return result;
	}

	operation.status = KnotStepStatus::InProgress;
	operation.terminalCode = KnotCode::Ok;
	operation.terminalMessage = "compare operation in progress";
	return KnotResult::success();
}

} // namespace

KnotCompareOperation::KnotCompareOperation()
    : _impl(new (std::nothrow) KnotCompareOperationImpl()) {
}

KnotCompareOperation::~KnotCompareOperation() {
	if (_impl != nullptr) {
		clearSecrets(*_impl);
	}
}

KnotStepResult KnotCompareOperation::step(uint32_t iterationBudget) {
	KnotStepResult result;
	if (_impl == nullptr) {
		result.code = KnotCode::InternalError;
		result.message = "compare operation allocation failed";
		result.status = KnotStepStatus::Failed;
		return result;
	}

	KnotCompareOperationImpl &impl = *_impl;
	if (impl.status != KnotStepStatus::InProgress) {
		if (impl.status == KnotStepStatus::Idle) {
			result.code = KnotCode::NotInitialized;
			result.message = "compare operation has not been started";
			result.status = KnotStepStatus::Failed;
			return result;
		}
		return makeStepResult(impl);
	}
	if (iterationBudget == 0) {
		return failOperation(impl, KnotCode::InvalidArgument, "iteration budget must be greater than zero");
	}

	uint32_t completedThisStep = 0;
	while (completedThisStep < iterationBudget && impl.currentIteration < impl.totalIterations) {
		KnotResult cryptoResult;
		if (impl.currentIteration == 0) {
			uint8_t firstInput[KNOT_RAW_SALT_LENGTH + 4] = {};
			std::memcpy(firstInput, impl.salt, KNOT_RAW_SALT_LENGTH);
			firstInput[KNOT_RAW_SALT_LENGTH + 3] = 1;
			cryptoResult = internal::hmacSha256Digest(
			    impl.hmac,
			    firstInput,
			    sizeof(firstInput),
			    impl.u,
			    sizeof(impl.u)
			);
			internal::secureZero(firstInput, sizeof(firstInput));
			if (cryptoResult) {
				std::memcpy(impl.accumulated, impl.u, sizeof(impl.accumulated));
				std::memcpy(impl.derivedKeyBlock, impl.u, sizeof(impl.derivedKeyBlock));
			}
		} else {
			uint8_t nextU[KNOT_RAW_HASH_LENGTH] = {};
			cryptoResult = internal::hmacSha256Digest(
			    impl.hmac,
			    impl.u,
			    sizeof(impl.u),
			    nextU,
			    sizeof(nextU)
			);
			if (cryptoResult) {
				std::memcpy(impl.u, nextU, sizeof(impl.u));
				for (size_t i = 0; i < sizeof(impl.accumulated); i++) {
					impl.accumulated[i] ^= impl.u[i];
				}
				std::memcpy(
				    impl.derivedKeyBlock,
				    impl.accumulated,
				    sizeof(impl.derivedKeyBlock)
				);
			}
			internal::secureZero(nextU, sizeof(nextU));
		}

		if (!cryptoResult) {
			return failOperation(impl, cryptoResult.code, cryptoResult.message);
		}
		impl.currentIteration++;
		impl.completedIterations = impl.currentIteration;
		completedThisStep++;
	}

	if (impl.currentIteration < impl.totalIterations) {
		impl.terminalMessage = "compare operation in progress";
		return makeStepResult(impl);
	}

	const bool match = impl.useConstantTimeCompare
	    ? internal::constantTimeEqual(
	          impl.derivedKeyBlock,
	          impl.expectedHash,
	          sizeof(impl.derivedKeyBlock)
	      )
	    : std::memcmp(impl.derivedKeyBlock, impl.expectedHash, sizeof(impl.derivedKeyBlock)) == 0;
	const uint32_t total = impl.totalIterationsSnapshot;
	clearSecrets(impl);
	impl.completedIterations = total;
	impl.totalIterationsSnapshot = total;
	impl.terminalMatch = match;
	impl.status = KnotStepStatus::Complete;
	impl.terminalCode = KnotCode::Ok;
	impl.terminalMessage = "compare operation complete";
	return makeStepResult(impl);
}

KnotResult KnotCompareOperation::cancel() {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "compare operation allocation failed");
	}
	if (_impl->status != KnotStepStatus::InProgress) {
		return KnotResult::success("compare operation is not active");
	}

	const uint32_t completed = _impl->currentIteration;
	const uint32_t total = _impl->totalIterationsSnapshot;
	clearSecrets(*_impl);
	_impl->completedIterations = completed;
	_impl->totalIterationsSnapshot = total;
	_impl->terminalMatch = false;
	_impl->status = KnotStepStatus::Cancelled;
	_impl->terminalCode = KnotCode::Ok;
	_impl->terminalMessage = "compare operation cancelled";
	return KnotResult::success("compare operation cancelled");
}

bool KnotCompareOperation::active() const {
	return _impl != nullptr && _impl->status == KnotStepStatus::InProgress;
}

KnotResult Knot::beginCompare(
    KnotCompareOperation &operation,
    const char *password,
    const char *encodedHash
) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (operation._impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "compare operation allocation failed");
	}
	if (operation._impl->status == KnotStepStatus::InProgress) {
		return KnotResult::failure(KnotCode::AlreadyInitialized, "compare operation is already active");
	}

	resetOperation(*operation._impl);
	{
		KnotLock lock(_impl->mutex, _impl->config.useMutex);
		if (!lock) {
			return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
		}
		KnotResult result = ensureReady(_impl.get());
		if (!result) {
			return result;
		}
		size_t passwordSize = 0;
		result = boundedCStringLength(password, _impl->config.maxPasswordLength, passwordSize);
		if (!result) {
			return result;
		}
		result = prepareLocked(
		    *_impl,
		    *operation._impl,
		    reinterpret_cast<const uint8_t *>(password),
		    passwordSize,
		    encodedHash
		);
		if (!result) {
			resetOperation(*operation._impl);
			return result;
		}
	}
	return initializeHmac(*operation._impl);
}

KnotResult Knot::beginCompare(
    KnotCompareOperation &operation,
    const uint8_t *password,
    size_t passwordLen,
    const char *encodedHash
) {
	if (_impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "knot allocation failed");
	}
	if (operation._impl == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "compare operation allocation failed");
	}
	if (operation._impl->status == KnotStepStatus::InProgress) {
		return KnotResult::failure(KnotCode::AlreadyInitialized, "compare operation is already active");
	}

	resetOperation(*operation._impl);
	{
		KnotLock lock(_impl->mutex, _impl->config.useMutex);
		if (!lock) {
			return KnotResult::failure(KnotCode::InternalError, "failed to lock knot");
		}
		KnotResult result = prepareLocked(
		    *_impl,
		    *operation._impl,
		    password,
		    passwordLen,
		    encodedHash
		);
		if (!result) {
			resetOperation(*operation._impl);
			return result;
		}
	}
	return initializeHmac(*operation._impl);
}

} // namespace zek::knot
