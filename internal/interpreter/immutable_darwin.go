package interpreter

// isImmutable on macOS always returns false (not supported).
func isImmutable(_ string) bool {
	return false
}
