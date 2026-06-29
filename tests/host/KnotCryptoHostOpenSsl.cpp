#include <internal/KnotCrypto.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace zek::knot::internal {

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

const char *cryptoBackendName() {
	return "openssl-host-test";
}

} // namespace zek::knot::internal
