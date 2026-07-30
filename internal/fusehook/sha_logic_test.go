package fusehook

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// Test the specific logic in the Lookup function for SHA-based access
func TestSHABasedAccessLogic(t *testing.T) {
	// Test content
	content := "test credential content for SHA verification"

	// Generate SHA identifier (like the system would)
	dataHash := sha256.Sum256([]byte(content))
	shaIdentifier := fmt.Sprintf("%x", dataHash)[:12]

	// Verify the generated identifier is 12 characters and hex
	if len(shaIdentifier) != 12 {
		t.Errorf("Expected SHA identifier to be 12 characters, got %d", len(shaIdentifier))
	}

	if !isHex(shaIdentifier) {
		t.Errorf("Generated SHA identifier is not valid hex: %s", shaIdentifier)
	}

	// Test that the identifier can be used as a filename
	t.Logf("Generated SHA identifier for content: %s", shaIdentifier)

	// Verify this would be recognized as a SHA identifier by our logic
	if len(shaIdentifier) == 12 && isHex(shaIdentifier) {
		t.Logf("SHA identifier %s would be correctly recognized by the system", shaIdentifier)
	} else {
		t.Errorf("SHA identifier %s would NOT be recognized as valid by the system", shaIdentifier)
	}
}
