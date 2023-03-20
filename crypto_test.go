package gostashcat

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := "Der Zugang zu Computern und allem, was einem zeigen kann, wie diese Welt funktioniert, sollte unbegrenzt und vollständig sein."
	// generate new symmetric encryption key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Could not generate key: %v\n", err)
	}
	ct, iv, err := encryptAES([]byte(plaintext), []byte(key))
	if err != nil {
		t.Fatalf("Could not encrypt: %v\n", err)
	}

	newPlainText, err := decryptAESHex(ct, iv, []byte(key))
	if err != nil {
		t.Fatalf("Could not decrypt: %v\n", err)
	}

	if plaintext != newPlainText {
		t.Fatalf("Encryption and Decryption did not lead to the initial plaintext! '%s' vs. '%s'", plaintext, newPlainText)
	}
}
