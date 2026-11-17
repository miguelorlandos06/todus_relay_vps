package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveAESKeyDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	k1 := deriveAESKey(secret)
	k2 := deriveAESKey(secret)
	if !bytes.Equal(k1, k2) {
		t.Fatal("deriveAESKey debe ser determinista para mismo secreto")
	}
	if len(k1) != 32 {
		t.Fatalf("clave debe ser 32 bytes (AES-256), got %d", len(k1))
	}
}

func TestDeriveAESKeyDifferentSecrets(t *testing.T) {
	s1 := bytes.Repeat([]byte{1}, 32)
	s2 := bytes.Repeat([]byte{2}, 32)
	if bytes.Equal(deriveAESKey(s1), deriveAESKey(s2)) {
		t.Fatal("claves derivadas de secretos distintos deben diferir")
	}
}

func TestEncryptDecryptAESGCMRoundTrip(t *testing.T) {
	key := deriveAESKey(bytes.Repeat([]byte{0xAB}, 32))
	cases := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello world"),
		bytes.Repeat([]byte{0xFF}, 262144), // 256 KiB
	}
	for i, plain := range cases {
		blob, err := encryptAESGCM(key, plain)
		if err != nil {
			t.Fatalf("case %d encrypt: %v", i, err)
		}
		if len(blob) <= NonceSize {
			t.Fatalf("case %d blob demasiado corto", i)
		}
		dec, err := decryptAESGCM(key, blob)
		if err != nil {
			t.Fatalf("case %d decrypt: %v", i, err)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("case %d mismatch", i)
		}
	}
}

func TestDecryptAESGCMTampered(t *testing.T) {
	key := deriveAESKey(bytes.Repeat([]byte{0xCD}, 32))
	blob, _ := encryptAESGCM(key, []byte("secreto"))
	blob[len(blob)-1] ^= 0x01 // mutar ciphertext
	if _, err := decryptAESGCM(key, blob); err == nil {
		t.Fatal("esperaba error de autenticidad GCM al mutar ciphertext")
	}
}

func TestDecryptAESGCMWrongKey(t *testing.T) {
	k1 := deriveAESKey(bytes.Repeat([]byte{1}, 32))
	k2 := deriveAESKey(bytes.Repeat([]byte{2}, 32))
	blob, _ := encryptAESGCM(k1, []byte("secreto"))
	if _, err := decryptAESGCM(k2, blob); err == nil {
		t.Fatal("esperaba error al descifrar con clave equivocada")
	}
}
