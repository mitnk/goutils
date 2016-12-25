package encrypt

import (
	"bytes"
	"testing"
)


func TestDecryptString(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	// this text was generated via Python
	encoded := "iEtr9vuP3i3PqO0oSOK8yg8t99JmwlNjYWTZVf03bK0btYjeY7gvxATnOSilrOAE"
	decoded, _ := DecryptString(encoded, key)
	if decoded != "网址：mitnk.com" {
		t.Fail()
	}
}


func TestEncryptDecrypt(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	src := []byte("foobar")
	encoded := Encrypt(src, key)
	decoded, _ := Decrypt(encoded, key)
	if !bytes.Equal(decoded, src) {
		t.Fail()
	}
}


func TestEncryptString(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	src := "网址：mitnk.com"
	encrypted_text := EncryptToString([]byte(src), key)
	decoded, _ := DecryptString(encrypted_text, key)
	if decoded != src {
		t.Fail()
	}
}
