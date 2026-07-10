# Examples

| Example | Description |
| --- | --- |
| `BasicHash` | Minimal init, hash, and compare flow. |
| `CooperativeCompare` | Verifies a stored hash with bounded PBKDF2 steps and yields between calls. |
| `ExplicitCost` | Uses `hash(password, cost)` and reads the stored cost. |
| `ManualSalt` | Generates an encoded salt first, then hashes with it. |
| `CallerBuffer` | Avoids result-owned output buffers. |
| `NeedsRehash` | Checks whether a stored hash should be upgraded. |
| `HashInfo` | Prints algorithm, version, and cost metadata. |
| `Configuration` | Sets cost and password length limits. |
| `ClassUsage` | Wraps Knot in an application class. |
| `Benchmark` | Prints target, cost, iterations, hash time, compare time, and heap values. |

Start with `BasicHash`. Use `CooperativeCompare` for request handling or Worker jobs that cannot block for the full PBKDF2 duration, then use `CallerBuffer` if your application has strict storage ownership rules.

Most examples explicitly configure cost 4 so they build and run quickly in CI and during demos. Production firmware should benchmark cost 14 and the cooperative iteration budget on target hardware before choosing lower values.
