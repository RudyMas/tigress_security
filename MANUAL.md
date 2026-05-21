# Tigress Security — Programmer's Manual

## Overview

`Tigress\Security` is a PHP 8.5+ library providing request access control, referer validation, and password hashing utilities for the Tigress Framework.

## Installation

```bash
composer require tigress/security
```

Requires PHP `^8.5` and the `tigress/core` package (dev dependency) which provides the global `CONFIG` constant.

## Dependencies

The constructor reads server entries from `CONFIG->servers`. Your application must define this global `CONFIG` object with a `servers` property (e.g., via `tigress/core`):

```php
// Example CONFIG structure expected:
CONFIG->servers = [
    'example.com' => 'production',
    'api.example.com' => 'production',
];
```

## API Reference

### `version(): string`

Returns the library version string.

```php
echo Security::version(); // "2026.01.08"
```

### `__construct()`

Initializes the allowed-sites list from `CONFIG->servers`. Each server key is added as an allowed referer host.

```php
$security = new Security();
// $this->sites will contain all server hostnames from CONFIG->servers
```

### `setSites(array $sites): void`

Override the list of allowed referer hosts.

```php
$security->setSites(['mydomain.com', 'admin.mydomain.com']);
```

### `checkAccess(?array $destinationPaths = null): void`

Validates the current HTTP request:

- If `HTTP_REFERER` is set: checks that the referer host is in the allowed sites list. If not, returns `403 Forbidden` and exits.
- If `HTTP_REFERER` is **not** set:
  - If `$destinationPaths` is provided: allows the request only if `REQUEST_URI` matches one of the given paths (wildcard `*` supported). Otherwise, `403`.
  - If `$destinationPaths` is `null`: always returns `403 Forbidden`.

```php
// Allow requests without referer only for /api/ and /webhook/
$security->checkAccess(['/api/*', '/webhook/receive']);
```

### `checkReferer(array $referencePaths): void`

Validates that `HTTP_REFERER` is present and matches one of the given path patterns. Returns `403` and exits if either condition fails.

```php
// Only allow requests coming from /admin/ or /dashboard/
$security->checkReferer(['/admin/*', '/dashboard']);
```

### `createHash(string $password, string $salt): string`

Returns a SHA-256 hash of the password concatenated with the salt.

> **Note:** SHA-256 is **not** suitable for password storage in production. Use `password_hash()` with bcrypt/argon2 instead. This method is provided for legacy compatibility.

```php
$hash = $security->createHash('myPassword', $salt);
```

### `createSalt(): string`

Generates a 64-character hexadecimal salt from 32 cryptographically random bytes.

```php
$salt = $security->createSalt(); // e.g. "a1b2c3d4..."
```

### `verifyHash(string $password, string $salt, string $hash): bool`

Timing-safe verification of a password against a stored hash. Uses `hash_equals()` to prevent timing attacks.

```php
if ($security->verifyHash($password, $salt, $storedHash)) {
    // password matches
}
```

## Path Matching (Wildcard `*`)

The `checkAccess()` and `checkReferer()` methods support the `*` wildcard in path segments:

| Pattern | Matches |
|---------|---------|
| `/admin/*` | `/admin/users`, `/admin/settings` |
| `/api/v1/*/status` | `/api/v1/users/status` |
| `/public/*` | `/public/`, `/public/file.js` |
| `*` | Any path |

## Error Handling

Access-control methods (`checkAccess`, `checkReferer`) abort execution with a `403 Forbidden` header on failure — no exceptions are thrown. Wrap them in a try-catch only if you modify the class to throw instead.

`createSalt()` throws `RandomException` if the system lacks a CSPRNG source.

## Code Review Notes

1. **Hard exit on 403**: `checkAccess()` and `checkReferer()` call `exit`, which terminates the PHP process. Framework users may prefer to throw an `HttpException` instead. Consider wrapping calls or subclassing.

2. **CONFIG global dependency**: The constructor depends on a global `CONST` constant (`CONFIG->servers`). If you use this library outside the Tigress Framework, call `setSites()` explicitly after construction.

3. **Password hashing**: `createHash()` uses plain SHA-256 without key stretching. Do **not** use for new password storage — prefer `password_hash()` / `password_verify()` with `PASSWORD_BCRYPT` or `PASSWORD_ARGON2ID`.

4. **Version mismatch**: The docblock `@version` (`2026.02.03.0`) differs from `version()` return value (`2026.01.08`).

5. **Typo in private methods**: Parameter `$referees` in `pathMatches()` and `pathsMatch()` is misspelled (should be `$referers` or `$segments`).
