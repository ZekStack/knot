# Security

Knot is for password hashing, not encryption.

OWASP currently prefers Argon2id for password storage, then scrypt. PBKDF2-HMAC-SHA256 is mainly the fallback path when Argon2id or scrypt are not available or appropriate. Knot targets constrained ESP32 firmware where a compact PBKDF2-based implementation may be the practical option. For current guidance, see the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

## Store hashes only

Store the encoded Knot hash string:

```txt
$knot$v1$c14$<salt>$<hash>
```

Do not store plaintext passwords.

## Compatibility

Knot is not bcrypt-compatible. It does not read or write `$2a$`, `$2b$`, or `$2y$` hashes.

## Cost tuning

Use the highest cost your login and provisioning flow can tolerate on real hardware. Cost 14 maps to 1,024,000 PBKDF2-HMAC-SHA256 iterations, which is above OWASP's current 600,000+ iteration guidance for PBKDF2-HMAC-SHA256. It may still be too slow for some ESP32 products.

Cost 14 is the secure default, not the demo setting. Lower the cost only with a documented latency and denial-of-service tradeoff.

NIST guidance fits Knot's format: store salted password hashes, store the cost factor, choose the cost as high as practical, and increase it over time.

Existing `$knot$v1$c10$...` hashes remain verifiable. They become rehash candidates when checked against the default cost 14.

## Comparison

`compare()` uses constant-time derived-key comparison by default. Leave `useConstantTimeCompare` enabled unless you have a controlled test-only reason to disable it.

## Input limits

The default password limit is 72 bytes. PBKDF2 does not require this limit; Knot keeps it as an embedded denial-of-service bound.

Knot hashes bytes, not characters. The `const char *` overloads hash the byte sequence up to the first NUL byte. The `const uint8_t *` plus length overloads are binary-safe and can hash embedded NUL bytes.

Knot does not normalize Unicode. Applications that normalize passwords must do so consistently before hashing and verification.

`nullptr` passwords are rejected even when length is `0`. Empty passwords are valid through `hash("")` or through a non-null byte pointer with length `0`.

## Threat model

Knot is appropriate for local device login and constrained firmware flows where the ESP32 verifies a password-derived hash locally.

For cloud credential storage, prefer a server-side password hashing scheme such as Argon2id or scrypt where available. Do not choose Knot for cloud storage only because its API looks familiar.

## Benchmarks

Fill this table from `examples/Benchmark` on the exact firmware and board profile used by the product.

| Target | Cost | Iterations | Hash time ms | Compare time ms | Free heap before/after | Notes |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| ESP32 | 14 | 1,024,000 | TBD | TBD | TBD | Measure on target |
| ESP32-S3 | 14 | 1,024,000 | TBD | TBD | TBD | Measure on target |
| ESP32-C3 | 14 | 1,024,000 | TBD | TBD | TBD | Measure on target |
| ESP32-P4 | 14 | 1,024,000 | TBD | TBD | TBD | Measure on target |
