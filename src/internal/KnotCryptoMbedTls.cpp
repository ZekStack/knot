#include "KnotCrypto.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include <cstring>

namespace zek::knot::internal {

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

const char *cryptoBackendName() {
	return "mbedtls";
}

} // namespace zek::knot::internal
