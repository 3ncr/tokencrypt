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

### Recommended: raw 32-byte key

Pass a 32-byte AES-256 key. Derive it however you prefer — for passwords use
Argon2id; for high-entropy inputs (random keys, API tokens) a single SHA3-256
hash is sufficient.

```golang
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil { /* ... */ }     // or: load from env / secret store
tokenCrypt, err := tokencrypt.NewRawTokenCrypt(key)
```

### Legacy: PBKDF2-SHA3 constructor

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated — prefer
`NewRawTokenCrypt` above for new code.

```golang  
tokenCrypt, err := tokencrypt.NewTokenCrypt(secret, salt, 1000)
```

`secret` and `salt` - are encryption keys (technically one of them is key, another is salt, but you need to store them both somewhere, preferably in different places). 

You can store them any preferred places: environment variables, files, shared memory, drive from hardware serial numbers or MAC addresses. Be creative. 

`1000` - is a number of PBKDF2 rounds. 
The more is better and slower. 
If you are sure that your secrets are long and random, you can keep this value reasonable low.  

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

 

