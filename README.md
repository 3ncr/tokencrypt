# tokencrypt (3ncr.org)

[![Lint & Test](https://github.com/3ncr/tokencrypt/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/tokencrypt/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/3ncr/tokencrypt.svg)](https://pkg.go.dev/github.com/3ncr/tokencrypt)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/3ncr/tokencrypt/badge)](https://scorecard.dev/viewer/?uri=github.com/3ncr/tokencrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the Go reference implementation. See
[github.com/3ncr](https://github.com/3ncr) for implementations in other
languages (Node.js, PHP, Python, Rust, Java, C#, Ruby).

## Install

```bash
go get github.com/3ncr/tokencrypt
```

Requires Go 1.22+.

## Usage

Pick a constructor based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key (random key, API token hashed to 32
bytes via SHA3-256, etc.), skip the KDF and pass it directly.

```go
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil { /* ... */ } // or: load from env / secret store
tokenCrypt, err := tokencrypt.NewRawTokenCrypt(key)
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `NewArgon2idTokenCrypt`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(`m=19456 KiB, t=2, p=1`). The salt must be at least 16 bytes.

```go
tokenCrypt, err := tokencrypt.NewArgon2idTokenCrypt(secret, salt)
```

### Legacy: PBKDF2-SHA3 (existing data only)

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated —
prefer `NewRawTokenCrypt` or `NewArgon2idTokenCrypt` for new code.

```go
tokenCrypt, err := tokencrypt.NewTokenCrypt(secret, salt, 1000)
```

`secret` and `salt` are inputs to PBKDF2-SHA3 (technically one is the key, the
other is the salt, but you need to store them both somewhere, preferably in
different places).

### Encrypt / decrypt

After constructing an instance, use `Encrypt3ncr` and `DecryptIf3ncr`:

```go
token := "08019215-B205-4416-B2FB-132962F9952F" // your secret you want to encrypt
encryptedSecretToken, _ := tokenCrypt.Encrypt3ncr(token)
// encryptedSecretToken == "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"

// ... some time later in another context ...

decryptedSecretToken, _ := tokenCrypt.DecryptIf3ncr(encryptedSecretToken)
// decryptedSecretToken == "08019215-B205-4416-B2FB-132962F9952F"
```

`DecryptIf3ncr` returns the input unchanged when it does not start with the
`3ncr.org/1#` header, so it is safe to route every configuration value through
it regardless of whether it was encrypted.

## Command line utility

`tokencrypt-cmd` is an interactive command-line utility that does
encryption / decryption.

## License

MIT — see [LICENSE](LICENSE).
