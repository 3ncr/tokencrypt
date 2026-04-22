# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-04-22

First tagged release. Stable API for the
[3ncr.org v1](https://3ncr.org/1/) encryption envelope (AES-256-GCM,
12-byte random IV, 16-byte GCM tag).

### Added

- `NewRawTokenCrypt(key)` — primary constructor for callers with a 32-byte
  AES-256 key.
- `NewArgon2idTokenCrypt(secret, salt)` — Argon2id KDF for password-strength
  secrets. Parameters match the [3ncr.org v1 spec](https://3ncr.org/1/#kdf):
  `m=19456 KiB, t=2, p=1`, 32-byte output, salt ≥ 16 bytes.

### Changed

- `NewTokenCrypt(secret, salt, iterations)` (PBKDF2-SHA3) is now documented
  as legacy; kept for backward compatibility with data encrypted by earlier
  versions. Prefer `NewRawTokenCrypt` or `NewArgon2idTokenCrypt` for new code.
- Go 1.22+ required. CI runs the `stable` and `1.25` toolchains.
- Migrated CI from Travis to GitHub Actions; added `go mod verify` and
  `golangci-lint v2.7.0`.
- Bumped `golang.org/x/crypto` to `v0.50.0`.

[1.0.0]: https://github.com/3ncr/tokencrypt/releases/tag/v1.0.0
