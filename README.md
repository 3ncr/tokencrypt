# tokencrypt (3ncr.org)

3ncr.org is a standard for string encryption/decryption (algorithms + storage format). Originally it was intended for 
encryption tokens in configuration files.  

3ncr.org v1 uses modern cryptographic primitives (SHA3-256, AES-256-GCM) and is fairly simple: 
```    
    header + base64(iv + data + tag) 
```

Encrypted data looks like this `3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`

This is a golang implementation.

## Usage

Pick a constructor based on the kind of secret you have:

### Recommended: Argon2id (low-entropy secrets)

For passwords or passphrases, use `NewArgon2idTokenCrypt`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf):
m=19456 KiB, t=2, p=1. The salt must be at least 16 bytes.

```golang
tokenCrypt, err := tokencrypt.NewArgon2idTokenCrypt(secret, salt)
```

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key (random key, API token hashed to 32
bytes via SHA3-256, etc.), skip the KDF and pass it in directly.

```golang
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil { /* ... */ }     // or: load from env / secret store
tokenCrypt, err := tokencrypt.NewRawTokenCrypt(key)
```

### Legacy: PBKDF2-SHA3 constructor

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated —
prefer `NewArgon2idTokenCrypt` or `NewRawTokenCrypt` for new code.

```golang
tokenCrypt, err := tokencrypt.NewTokenCrypt(secret, salt, 1000)
```

`secret` and `salt` are encryption inputs (technically one of them is the key, the other is the salt, but you need to store them both somewhere, preferably in different places).

You can store them in any preferred places: environment variables, files, shared memory, derived from hardware serial numbers or MAC addresses. Be creative.

### Encrypt / decrypt

After you created an instance, you can just use Encrypt3ncr and DecryptIf3ncr methods:

```golang 
token := "08019215-B205-4416-B2FB-132962F9952F"; // your secret you want to encrypt 
encryptedSecretToken, _ := tokenCrypt.Encrypt3ncr(token);
// now encryptedSecretToken == "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"

// ... some time later in another context ...  

decryptedSecretToken, _ = tokenCrypt.DecryptIf3ncr(encryptedSecretToken); 
// now decryptedSecretToken == "08019215-B205-4416-B2FB-132962F9952F";
```

Method DecryptIf3ncr returns the same string if supplied argument does not start with 3ncr.org value. It is safe to pass through it all values from your configuration file. 

## Command line utility

`tokencrypt-cmd` is an interactive command-line utility that does encryption/decryption

 

