package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// deriveAESKey deriva una clave AES-256 (32 bytes) a partir del secreto
// compartido vía HMAC-SHA256 con un info fijo. Usar un info fijo vincula
// la clave derivada a esta versión del protocolo, de modo que un cambio
// de versión rota la clave automáticamente.
//
// Es una KDF simple (no HKDF), suficiente para nuestro caso: el secreto
// ya es de 32+ bytes con alta entropía.
func deriveAESKey(secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("todus-relay-v1/encryption-key"))
	return h.Sum(nil) // 32 bytes → AES-256
}

// encryptAESGCM cifra plaintext con AES-GCM y un nonce aleatorio fresco.
// Devuelve nonce(12) || ciphertext donde ciphertext ya incluye el tag GCM.
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil) // tag appended
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptAESGCM abre un blob con formato nonce(12) || ciphertext||tag.
func decryptAESGCM(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns+gcm.Overhead() {
		return nil, errors.New("blob demasiado corto para AES-GCM")
	}
	nonce := blob[:ns]
	ciphertext := blob[ns:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
