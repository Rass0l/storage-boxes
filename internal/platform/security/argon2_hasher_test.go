package security

import "testing"

func TestArgon2idHasherRoundTrip(t *testing.T) {
	h := NewArgon2idHasher()
	h.Params.Memory = 8 * 1024
	h.Params.Time = 1
	h.Params.Threads = 1

	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := h.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected match")
	}
	ok, err = h.Verify("wrong", encoded)
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if ok {
		t.Fatal("expected mismatch")
	}
}

func TestArgon2idHasherRejectsBadEncoding(t *testing.T) {
	h := NewArgon2idHasher()
	if _, err := h.Verify("x", "$bcrypt$..."); err == nil {
		t.Fatal("expected error on non-argon2id hash")
	}
}
