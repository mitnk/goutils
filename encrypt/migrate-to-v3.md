# Migration Guide: AES-CBC to AES-GCM

This guide helps you migrate from `goutils/encrypt` v2.x (AES-CBC) to v3.0 (AES-GCM).

## What Changed

| Aspect | v2.x (Old) | v3.0 (New) |
|--------|----------|----------|
| Cipher mode | AES-CBC | AES-GCM |
| Authentication | None | Built-in (AEAD) |
| Go version | 1.14+ | 1.21+ |
| IV/Nonce size | 16 bytes | 12 bytes |

## Breaking Change

**Data encrypted with v2.x (CBC) cannot be decrypted with v3.0 (GCM).**

The ciphertext formats are incompatible. You must re-encrypt any stored data during migration.

## Migration Steps

### Step 1: Update Your Go Version

Ensure you're using Go 1.21 or later:

```bash
go version
```

### Step 2: Update the Dependency

```bash
go get -u github.com/mitnk/goutils/v3@v3.0.1
```

### Step 3: Migrate Existing Encrypted Data

If you have data encrypted with the old library, you'll need to:

1. Decrypt it using the **old** library
2. Re-encrypt it using the **new** library

Here's a helper script to migrate your data:

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "errors"
    "fmt"

    newencrypt "github.com/mitnk/goutils/v3/encrypt"
)

// Old CBC decryption functions (copy these temporarily)
func unpad(src []byte) ([]byte, error) {
    length := len(src)
    if length == 0 {
        return nil, errors.New("cannot unpad empty string")
    }
    unpadding := int(src[length-1])
    if unpadding > length {
        return nil, errors.New("unpad error")
    }
    return src[:(length - unpadding)], nil
}

func decryptCBC(ciphertext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    if len(ciphertext) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    if len(ciphertext)%aes.BlockSize != 0 {
        return nil, errors.New("ciphertext not full blocks")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]
    stream := cipher.NewCBCDecrypter(block, iv)
    stream.CryptBlocks(ciphertext, ciphertext)
    return unpad(ciphertext)
}

func decryptCBCString(ciphertext string, key []byte) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    decrypted, err := decryptCBC(data, key)
    return string(decrypted), err
}

// Migrate converts old CBC-encrypted data to new GCM format
func Migrate(oldCiphertext string, key []byte) (string, error) {
    // Decrypt with old CBC method
    plaintext, err := decryptCBCString(oldCiphertext, key)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt old data: %w", err)
    }

    // Re-encrypt with new GCM method
    newCiphertext := newencrypt.EncryptToString([]byte(plaintext), key)
    return newCiphertext, nil
}

func main() {
    key := []byte("your-16-byte-key")

    // Your old encrypted data
    oldEncrypted := "BASE64_ENCRYPTED_STRING_HERE"

    // Migrate to new format
    newEncrypted, err := Migrate(oldEncrypted, key)
    if err != nil {
        panic(err)
    }

    fmt.Println("New ciphertext:", newEncrypted)

    // Verify it works
    decrypted, err := newencrypt.DecryptString(newEncrypted, key)
    if err != nil {
        panic(err)
    }
    fmt.Println("Decrypted:", decrypted)
}
```

### Step 4: Update Your Application Code

The API remains the same, so your existing code should work without changes:

```go
import "github.com/mitnk/goutils/v3/encrypt"

key := []byte("abcdefghijklmnop") // 16 bytes for AES-128

// Encrypt
ciphertext := encrypt.EncryptToString([]byte("secret data"), key)

// Decrypt
plaintext, err := encrypt.DecryptString(ciphertext, key)
if err != nil {
    // Handle error - could be wrong key or tampered data
}
```

## Verifying Migration Success

After migration, verify your data:

```go
// Test that new encryption/decryption works
original := "test message"
encrypted := encrypt.EncryptToString([]byte(original), key)
decrypted, err := encrypt.DecryptString(encrypted, key)

if err != nil || decrypted != original {
    log.Fatal("Migration verification failed!")
}
```
