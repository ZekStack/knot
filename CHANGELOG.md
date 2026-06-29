# Changelog

## Unreleased

* Raised the default cost from 10 to 14.
* Added binary-safe password hashing and comparison overloads.
* Kept `nullptr, 0` password inputs invalid while documenting empty-password behavior.
* Made public state reads consistently lock through Knot's mutex path.
* Expanded public API edge-case and malformed-input host tests.
* Added sanitizer CI coverage for host tests.
* Added `examples/Benchmark` for target timing and heap measurements.
* Updated security documentation, bcrypt positioning, benchmark placeholders, and migration notes.

