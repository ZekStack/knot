# Security

Knot is for password hashing, not encryption.

## Store hashes only

Store the encoded Knot hash string:

```txt
$knot$v1$c10$<salt>$<hash>
```

Do not store plaintext passwords.

## Compatibility

Knot is not bcrypt-compatible. It does not read or write `$2a$`, `$2b$`, or `$2y$` hashes.

## Cost tuning

Use the highest cost your login and provisioning flow can tolerate on real hardware. A cost that is comfortable on a desktop may be too slow on an ESP32.

## Comparison

`compare()` uses constant-time derived-key comparison by default. Leave `useConstantTimeCompare` enabled unless you have a controlled test-only reason to disable it.

## Input limits

The default password limit is 72 bytes. This mirrors bcrypt-style expectations and keeps embedded work bounded.
