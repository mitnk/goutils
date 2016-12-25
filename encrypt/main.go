package encrypt

import (
	_ "fmt"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func pad(src []byte) []byte {
    padding := aes.BlockSize - len(src)%aes.BlockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(src, padtext...)
}

func unpad(src []byte) ([]byte, error) {
    length := len(src)
    unpadding := int(src[length-1])

    if unpadding > length {
        return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
    }

    return src[:(length - unpadding)], nil
}

func Encrypt(text, key []byte) []byte {
	text = pad(text)
	block, err := aes.NewCipher(key)
	check(err)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize + len(text))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	check(err)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return ciphertext
}

func DecryptString(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	check(err)
	decrypted, err := Decrypt(data, key)
	return string(decrypted), err
}

func EncryptToString(src, key []byte) string {
	encrypted := Encrypt(src, key)
	return base64.StdEncoding.EncodeToString(encrypted)
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	check(err)
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	text, err := unpad(ciphertext)
	if err != nil {
		return nil, err
	}
	return text, nil
}