# Changelog

## Unreleased

* Standardized the repository on the `main` branch.
* Made release creation depend on a fully green CI run for the tagged commit.
* Added package/tag version validation to prevent mismatched releases.
* Added blocking whitespace, clang-format, Arduino Lint, and release-changelog validation.
* Moved CI workloads to the ZekStack self-hosted runner with isolated build directories.
* Raised the default cost from 10 to 14.
* Added binary-safe password hashing and comparison overloads.
* Kept `nullptr, 0` password inputs invalid while documenting empty-password behavior.
* Made public state reads consistently lock through Knot's mutex path.
* Expanded public API edge-case and malformed-input host tests.
* Added sanitizer CI coverage for host tests.
* Added `examples/Benchmark` for target timing and heap measurements.
* Updated security documentation, bcrypt positioning, benchmark placeholders, and migration notes.
