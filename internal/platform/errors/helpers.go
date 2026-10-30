package errors

func New(category Category, code, message string) *DomainError {
	return &DomainError{
		Category: category,
		Code:     code,
		Message:  message,
		Metadata: map[string]any{},
	}
}
