#include "KnotCrypto.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include <cstring>
#include <new>

namespace zek::knot::internal {

struct HmacSha256Context {
	mbedtls_md_context_t context;
	bool initialized = false;
};

KnotResult randomBytes(uint8_t *output, size_t outputSize) {
	if (output == nullptr || outputSize == 0) {
		return KnotResult::failure(KnotCode::InvalidArgument, "output is required");
	}

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctrDrbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctrDrbg);

	const char personalization[] = "knot";
	int rc = mbedtls_ctr_drbg_seed(
	    &ctrDrbg,
	    mbedtls_entropy_func,
	    &entropy,
	    reinterpret_cast<const unsigned char *>(personalization),
	    std::strlen(personalization)
	);
	if (rc == 0) {
		rc = mbedtls_ctr_drbg_random(&ctrDrbg, output, outputSize);
	}

	mbedtls_ctr_drbg_free(&ctrDrbg);
	mbedtls_entropy_free(&entropy);

	if (rc != 0) {
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

	const int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(
	    MBEDTLS_MD_SHA256,
	    password,
	    passwordSize,
	    salt,
	    saltSize,
	    iterations,
	    static_cast<uint32_t>(outputSize),
	    output
	);

	if (rc != 0) {
		return KnotResult::failure(KnotCode::HashFailed, "password hashing failed");
	}

	return KnotResult::success();
}

KnotResult hmacSha256Create(
    HmacSha256Context *&context,
    const uint8_t *key,
    size_t keySize
) {
	if (context != nullptr || key == nullptr) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid hmac input");
	}

	HmacSha256Context *created = new (std::nothrow) HmacSha256Context();
	if (created == nullptr) {
		return KnotResult::failure(KnotCode::InternalError, "hmac allocation failed");
	}
	mbedtls_md_init(&created->context);

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	int rc = mdInfo == nullptr ? -1 : mbedtls_md_setup(&created->context, mdInfo, 1);
	if (rc == 0) {
		rc = mbedtls_md_hmac_starts(&created->context, key, keySize);
	}
	if (rc != 0) {
		mbedtls_md_free(&created->context);
		secureZero(created, sizeof(*created));
		delete created;
		return KnotResult::failure(KnotCode::CryptoError, "hmac initialization failed");
	}

	created->initialized = true;
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
	if (context == nullptr || !context->initialized ||
	    (input == nullptr && inputSize != 0) || output == nullptr ||
	    outputSize < KNOT_RAW_HASH_LENGTH) {
		return KnotResult::failure(KnotCode::InvalidArgument, "invalid hmac input");
	}

	int rc = mbedtls_md_hmac_reset(&context->context);
	if (rc == 0 && inputSize != 0) {
		rc = mbedtls_md_hmac_update(&context->context, input, inputSize);
	}
	if (rc == 0) {
		rc = mbedtls_md_hmac_finish(&context->context, output);
	}
	if (rc != 0) {
		return KnotResult::failure(KnotCode::HashFailed, "hmac calculation failed");
	}
	return KnotResult::success();
}

void hmacSha256Destroy(HmacSha256Context *&context) {
	if (context == nullptr) {
		return;
	}
	mbedtls_md_free(&context->context);
	context->initialized = false;
	secureZero(context, sizeof(*context));
	delete context;
	context = nullptr;
}

const char *cryptoBackendName() {
	return "mbedtls";
}

} // namespace zek::knot::internal
