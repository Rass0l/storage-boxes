package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, KEKLen)
	for i := range key {
		key[i] = byte(i)
	}
	plain := []byte("hello vault")
	nonce, ct, err := SealWithKEK(key, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(nonce) != 12 || bytes.Equal(ct, plain) {
		t.Fatalf("nonce/ct malformed")
	}
	got, err := OpenWithKEK(key, nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	a := make([]byte, KEKLen)
	b := make([]byte, KEKLen)
	for i := range a {
		a[i] = 0x11
		b[i] = 0x22
	}
	nonce, ct, _ := SealWithKEK(a, []byte("x"))
	if _, err := OpenWithKEK(b, nonce, ct); err == nil {
		t.Fatal("expected error opening with wrong key")
	}
}
