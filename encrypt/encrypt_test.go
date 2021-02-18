package encrypt

import (
	"bytes"
	"testing"
)


func TestEncryptDecrypt(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	src := []byte("foobar")
	encoded := Encrypt(src, key)
	decoded, _ := Decrypt(encoded, key)
	if !bytes.Equal(decoded, src) {
		t.Fail()
	}

	src = []byte("abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmno" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop" +
				 "p..abcdefghijklmnop..abcdefghijklmnop..abcdefghijklmnop")
	encoded = Encrypt(src, key)
	decoded, _ = Decrypt(encoded, key)
	if !bytes.Equal(decoded, src) {
		t.Fail()
	}
}


func TestEncryptString(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	src := "网址：github.com"
	encrypted_text := EncryptToString([]byte(src), key)
	decoded, _ := DecryptString(encrypted_text, key)
	if decoded != src {
		t.Fail()
	}
}

func TestEncryptEmptyString(t *testing.T) {
	key := []byte("abd2efghijklmnop")
	src := ""
	encrypted_text := EncryptToString([]byte(src), key)
	decoded, _ := DecryptString(encrypted_text, key)
	if decoded != src {
		t.Fail()
	}
}

func TestMisc(t *testing.T) {
	key := []byte("abd2efghijklmnop")
	src := "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
	encrypted_text := EncryptToString([]byte(src), key)
	decoded, _ := DecryptString(encrypted_text, key)
	if decoded != src {
		t.Fail()
	}
}
