#include <internal/KnotCrypto.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <new>

namespace zek::knot::internal {

struct HmacSha256Context {
	uint8_t key[KNOT_MAX_PASSWORD_LENGTH] = {};
	size_t keySize = 0;
};

KnotResult randomBytes(uint8_t *output, size_t outputSize) {
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "output is required");
	}
	if (RAND_bytes(output, static_cast<int>(outputSize)) != 1) {
		return KnotResult::failure(KnotCode::EntropyFailed, "secure random generation failed");
	}
	return KnotResult::success();
}

KnotResult pbkdf2Sha256(
    const uint8_t *password,
    size_t passwordSize,
    const uint8_t *salt,
    size_t saltSize,
    uint32_t iterations,
    uint8_t *output,
    size_t outputSize
) {
	if (password == nullptr || salt == nullptr || output == nullptr || iterations == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid crypto input");
	}

	const int rc = PKCS5_PBKDF2_HMAC(
	    reinterpret_cast<const char *>(password),
	    static_cast<int>(passwordSize),
	    salt,
	    static_cast<int>(saltSize),
	    static_cast<int>(iterations),
	    EVP_sha256(),
	    static_cast<int>(outputSize),
	    output
	);
	if (rc != 1) {
		return KnotResult::failure(KnotCode::HashFailed, "password hashing failed");
	}
	return KnotResult::success();
}

KnotResult hmacSha256Create(
    HmacSha256Context *&context,
    const uint8_t *key,
    size_t keySize
) {
	if (context != nullptr || key == nullptr || keySize > KNOT_MAX_PASSWORD_LENGTH) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid hmac input");
	}

	HmacSha256Context *created = new (std::nothrow) HmacSha256Context();
	if (created == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "hmac allocation failed");
	}
	if (keySize != 0) {
		std::memcpy(created->key, key, keySize);
	}
	created->keySize = keySize;
	context = created;
	return KnotResult::success();
}

KnotResult hmacSha256Digest(
    HmacSha256Context *context,
    const uint8_t *input,
    size_t inputSize,
    uint8_t *output,
    size_t outputSize
) {
	if (context == nullptr || (input == nullptr && inputSize != 0) || output == nullptr ||
	    outputSize < KNOT_RAW_HASH_LENGTH) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid hmac input");
	}

	unsigned int written = 0;
	if (HMAC(
	        EVP_sha256(),
	        context->key,
	        static_cast<int>(context->keySize),
	        input,
	        inputSize,
	        output,
	        &written
	    ) == nullptr ||
	    written != KNOT_RAW_HASH_LENGTH) {
		return KnotResult::failure(KnotCode::HashFailed, "hmac calculation failed");
	}
	return KnotResult::success();
}

void hmacSha256Destroy(HmacSha256Context *&context) {
	if (context == nullptr) {
		return;
	}
	secureZero(context, sizeof(*context));
	delete context;
	context = nullptr;
}

const char *cryptoBackendName() {
	return "openssl-host-test";
}

} // namespace zek::knot::internal
