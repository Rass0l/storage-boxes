package api

func ValidateCreateBoxRequest(req CreateBoxRequest) bool {
	return req.Name != "" && req.SizeBytes > 0
}
