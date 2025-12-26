package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Encrypt(text, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	aesGCM, err := cipher.NewGCM(block)
	check(err)

	// GCM uses a 12-byte nonce by default
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	check(err)

	// Seal appends the encrypted data to the nonce
	ciphertext := aesGCM.Seal(nonce, nonce, text, nil)
	return ciphertext
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: authentication error or incorrect key")
	}

	return plaintext, nil
}

func EncryptToString(src, key []byte) string {
	encrypted := Encrypt(src, key)
	return base64.StdEncoding.EncodeToString(encrypted)
}

func DecryptString(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, err := Decrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
