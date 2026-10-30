package errors

import "net/http"

type HTTPErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Meta    map[string]any `json:"meta,omitempty"`
}

func HTTPStatus(err *DomainError) int {
	if err == nil {
		return http.StatusInternalServerError
	}
	switch err.Category {
	case CategoryAuth:
		return http.StatusUnauthorized
	case CategoryAuthz:
		return http.StatusForbidden
	case CategoryValidation:
		return http.StatusBadRequest
	case CategoryConflict:
		return http.StatusConflict
	case CategoryNotFound:
		return http.StatusNotFound
	case CategoryRateLimit:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}
