package gostashcat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

func encryptRSA(content []byte, pubkey *rsa.PublicKey) (string, error) {
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rng, pubkey, content, []byte(""))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func encryptAES(plaintext []byte, encryptionKey []byte) (string, string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", "", err
	}

	if len(plaintext)%aes.BlockSize != 0 {
		padLength := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padding := bytes.Repeat([]byte{byte(padLength)}, padLength)
		plaintext = append(plaintext, padding...)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext[aes.BlockSize:]), hex.EncodeToString(iv), nil
}

func decryptAES(ciphertext, iv, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	length := len(ciphertext)
	if length < aes.BlockSize {
		return "", errors.New("Ciphertext is too short")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, length)
	mode.CryptBlocks(plaintext, ciphertext)

	// remove padding
	if length%aes.BlockSize != 0 {
		return "", errors.New("pkcs7 unpad: data is not aligned to blocks")
	}
	padLen := int(plaintext[length-1])
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > aes.BlockSize || padLen == 0 || !bytes.HasSuffix(plaintext, pad) {
		return "", errors.New("pkcs7 unpad: invalid padding")
	}

	return string(plaintext[:length-padLen]), nil
}

func decryptAESHex(ct string, i string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(ct)
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(i)
	if err != nil {
		return "", err
	}

	return decryptAES(ciphertext, iv, key)
}
