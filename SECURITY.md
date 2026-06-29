# Security Policy

Knot is an early-stage ESP32 password hashing library. Review the implementation, benchmark it on target hardware, and choose cost settings deliberately before using it in production firmware.

## Threat model

Knot is intended for local device login and constrained firmware flows where an ESP32 verifies a password-derived hash locally.

For cloud credential storage, prefer a server-side password hashing scheme such as Argon2id or scrypt where available. PBKDF2-HMAC-SHA256 is mainly a fallback path when preferred password hashing schemes are unavailable or unsuitable.

Knot hashes are self-contained strings:

```txt
$knot$v1$c<cost>$<salt>$<hash>
```

The stored cost factor allows applications to verify older hashes and rehash them over time.

## Cost guidance

Cost 14 is the secure default and maps to 1,024,000 PBKDF2-HMAC-SHA256 iterations. It is not the demo or test setting.

Production firmware must benchmark cost 14 on the target ESP32 board and may lower the cost only with a documented latency and denial-of-service tradeoff.

Existing `$knot$v1$c10$...` hashes remain verifiable. They become rehash candidates when checked against the default cost 14.

## Input handling

Knot hashes bytes, not characters. The `const char *` overloads hash bytes up to the first NUL byte. The `const uint8_t *` plus length overloads are binary-safe and can hash embedded NUL bytes.

Knot does not normalize Unicode. Applications that normalize passwords must do so consistently before hashing and verification.

`nullptr` passwords are rejected even when length is `0`. Empty passwords are valid through `hash("")` or through a non-null byte pointer with length `0`.

## Reporting vulnerabilities

Report security issues privately to the repository maintainer. Do not open a public issue with exploit details before the maintainer has had time to investigate.

Include:

* affected version or commit
* reproduction steps
* target board and framework version if ESP32-specific
* expected and actual behavior

