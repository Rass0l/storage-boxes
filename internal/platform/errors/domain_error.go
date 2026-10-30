package errors

import "fmt"

type Category string

const (
	CategoryAuth       Category = "auth"
	CategoryAuthz      Category = "authz"
	CategoryVault      Category = "vault"
	CategoryShare      Category = "share"
	CategoryCrypto     Category = "crypto"
	CategoryQuota      Category = "quota"
	CategoryRateLimit  Category = "rate_limit"
	CategoryValidation Category = "validation"
	CategoryConflict   Category = "conflict"
	CategoryNotFound   Category = "not_found"
	CategoryInternal   Category = "internal"
)

type DomainError struct {
	Category Category
	Code     string
	Message  string
	Metadata map[string]any
	Cause    error
}

func (e *DomainError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", e.Category, e.Code, e.Message)
}

func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
