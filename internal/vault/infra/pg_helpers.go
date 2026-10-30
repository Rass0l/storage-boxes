package infra

import (
	"encoding/base64"
	"encoding/json"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func fromBase64Std(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// jsonMarshal wraps encoding/json.Marshal to keep call sites tidy.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
