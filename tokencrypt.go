package tokencrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"io"
	"strings"
)

const aes256KeySize = 32
const headerV1 = "3ncr.org/1#"
const nonceSizeV1 = 12

// Argon2id parameters recommended by the 3ncr.org v1 spec for low-entropy
// secrets. See https://3ncr.org/1/#kdf.
const (
	argon2idMemoryKiB  uint32 = 19456
	argon2idTime       uint32 = 2
	argon2idThreads    uint8  = 1
	argon2idMinSaltLen        = 16
)

type EncToken struct {
	aesgcm cipher.AEAD
}

// NewTokenCrypt returns a new 3ncr.org encrypter / decrypter.
// It derives AES-256 key using PBKDF2 with SHA3-256.
//
// Deprecated: PBKDF2-SHA3 is the legacy KDF, retained for decrypting
// existing 3ncr.org data. New callers should use [NewArgon2idTokenCrypt]
// for low-entropy secrets (passwords) or [NewRawTokenCrypt] for
// high-entropy keys (random 32-byte keys, SHA3-256 of an API token, etc.).
// See the 3ncr.org spec Key Derivation section.
func NewTokenCrypt(secret []byte, salt []byte, iter int) (*EncToken, error) {
	raw := pbkdf2.Key(secret, salt, iter, aes256KeySize, sha3.New256)
	return NewRawTokenCrypt(raw)
}

// NewArgon2idTokenCrypt returns a new 3ncr.org encrypter / decrypter
// whose AES-256 key is derived from secret and salt using Argon2id with
// the parameters recommended by the 3ncr.org v1 spec for low-entropy
// secrets (m=19456 KiB, t=2, p=1). salt must be at least 16 bytes.
func NewArgon2idTokenCrypt(secret []byte, salt []byte) (*EncToken, error) {
	if len(salt) < argon2idMinSaltLen {
		return nil, fmt.Errorf("salt must be at least %d bytes", argon2idMinSaltLen)
	}
	raw := argon2.IDKey(secret, salt, argon2idTime, argon2idMemoryKiB, argon2idThreads, aes256KeySize)
	return NewRawTokenCrypt(raw)
}

// NewRawTokenCrypt returns a new 3ncr.org encrypter / decrypter from a raw
// 32-byte AES-256 key. Derive the key however you prefer — Argon2id for
// passwords, a single SHA3-256 hash for high-entropy inputs (random keys, API
// tokens). See the 3ncr.org spec for recommended parameters.
func NewRawTokenCrypt(key []byte) (*EncToken, error) {
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("key size too small")
	}
	aesch, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(aesch, nonceSizeV1)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &EncToken{aesgcm: gcm}, nil
}

func (c *EncToken) decrypt(src string) (string, error) {
	buf, err := base64decode(src)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}

	if len(buf) < c.aesgcm.NonceSize() {
		return "", fmt.Errorf("truncated 3ncr token")
	}

	nonce := buf[:c.aesgcm.NonceSize()]
	data := buf[c.aesgcm.NonceSize():]

	plaintext, err := c.aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// Encrypt3ncr encrypts a string using most recent 3ncr.org version available
func (c *EncToken) Encrypt3ncr(source string) (string, error) {
	nonce := make([]byte, c.aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("rand nounce: %w", err)
	}
	ecnr := c.aesgcm.Seal(nil, nonce, []byte(source), nil)

	var b bytes.Buffer
	_, _ = b.Write(nonce)
	_, _ = b.Write(ecnr)

	return headerV1 + base64encode(b.Bytes()), nil
}

// DecryptIf3ncr decrypts a 3ncr.org string
// If the string does not starts with 3ncr.org header, it returns the argument unmodified and no error
func (c *EncToken) DecryptIf3ncr(source string) (string, error) {
	if !strings.HasPrefix(source, headerV1) {
		return source, nil
	}

	body := source[len(headerV1):]
	return c.decrypt(body)
}

func base64encode(src []byte) string {
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(src)
}

func base64decode(str string) ([]byte, error) {
	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(str)
}
