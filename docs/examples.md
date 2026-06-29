# Examples

| Example | Description |
| --- | --- |
| `BasicHash` | Minimal init, hash, and compare flow. |
| `ExplicitCost` | Uses `hash(password, cost)` and reads the stored cost. |
| `ManualSalt` | Generates an encoded salt first, then hashes with it. |
| `CallerBuffer` | Avoids result-owned output buffers. |
| `NeedsRehash` | Checks whether a stored hash should be upgraded. |
| `HashInfo` | Prints algorithm, version, and cost metadata. |
| `Configuration` | Sets cost and password length limits. |
| `ClassUsage` | Wraps Knot in an application class. |

Start with `BasicHash`, then use `CallerBuffer` if your application has strict storage ownership rules.
