# Bcrypt Positioning

Knot intentionally feels familiar to developers who have used Node `bcrypt`:

```js
const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync("password", salt);
const ok = bcrypt.compareSync("password", hash);
```

Knot equivalent:

```cpp
KnotSaltResult salt = knot.genSalt(10);
KnotHashResult hash = knot.hash("password", salt.value);
KnotCompareResult ok = knot.compare("password", hash.value);
```

## Important difference

Knot is not bcrypt. It does not produce bcrypt hashes and it does not verify bcrypt hashes.

Knot-owned format:

```txt
$knot$v1$c10$<salt>$<hash>
```

Bcrypt-style prefixes are reserved for actual bcrypt implementations:

```txt
$2a$
$2b$
$2y$
```

## Naming

Use `cost` in Knot documentation and configuration. `getRounds()` exists as a familiarity alias and returns the same value as `getCost()`.
