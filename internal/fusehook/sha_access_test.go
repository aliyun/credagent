package fusehook

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/guard"
	"github.com/aliyun/credagent/internal/osutil"
	"google.golang.org/protobuf/types/known/emptypb"
)

// MockBaselineMonitorService implements guard.MonitorService backed by a BaselineStore for testing
type MockBaselineMonitorService struct {
	baselineStore baseline.BaselineStore
}

func (m *MockBaselineMonitorService) RequestFUSEAccess(ctx context.Context, objectPath string, process osutil.ProcessInf, req *guard.FUSEAccessRequest) (*enclave.AccessResponse, error) {
	bl := m.baselineStore.GetBySha(objectPath)
	if bl == nil {
		bl = m.baselineStore.Get(objectPath)
	}

	if bl == nil {
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: "No baseline found for the requested object.",
		}, nil
	}

	return &enclave.AccessResponse{
		Status:  enclave.AccessStatus_ACCESS_GRANTED,
		FileSha: bl.SHA(),
	}, nil
}

func (m *MockBaselineMonitorService) CheckFileExistence(ctx context.Context, in *enclave.ProcessContext) (*enclave.FileExistenceResponse, error) {
	bl := m.baselineStore.GetBySha(in.GetObjectPath())
	if bl == nil {
		bl = m.baselineStore.Get(in.GetObjectPath())
	}

	if bl == nil {
		return &enclave.FileExistenceResponse{
			Exists:       false,
			IsProtected:  false,
			DenialReason: "No baseline found for the requested object.",
		}, nil
	}

	var protoPerms *enclave.FilePerms
	if p := bl.Metadata().Permissions; p != nil {
		protoPerms = &enclave.FilePerms{Uid: p.UID, Gid: p.GID, Mode: p.Mode}
	} else {
		protoPerms = &enclave.FilePerms{Mode: 0444, Uid: 0, Gid: 0}
	}

	return &enclave.FileExistenceResponse{
		Exists:       true,
		IsProtected:  true,
		DenialReason: "",
		Permissions:  protoPerms,
	}, nil
}

func (m *MockBaselineMonitorService) ListProtectedFiles(ctx context.Context, in *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error) {
	return &enclave.ListProtectedFilesResponse{
		Success: true,
		Message: "Successfully retrieved protected files",
	}, nil
}

func TestSHA256Access(t *testing.T) {
	tempDir := t.TempDir()

	testFilePath := filepath.Join(tempDir, "test_secret.txt")
	testContent := "this is a test secret"

	err := os.WriteFile(testFilePath, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	dataHash := sha256.Sum256([]byte(testContent))
	shaIdentifier := fmt.Sprintf("%x", dataHash)[:12]

	memStore := baseline.NewInMemoryBaselineStore()

	testBaseline := baseline.NewCredentialBaseline(
		shaIdentifier,
		baseline.FileMetadata{
			TargetPath: testFilePath,
		},
		&baseline.AccessRule{
			AllowedPrograms:      []string{"/usr/bin/test_binary"},
			VerificationStrategy: "ONE_TIME_USE",
		},
		[]byte(testContent),
	)

	err = memStore.Save(testBaseline)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	mockMonitor := &MockBaselineMonitorService{
		baselineStore: memStore,
	}

	shieldedNode := NewShieldedNode(mockMonitor, memStore)

	isProtected := shieldedNode.isProtectedFile(shaIdentifier)
	if !isProtected {
		t.Error("Expected SHA identifier to be recognized as protected file")
	}

	isProtected2 := shieldedNode.isProtectedFile(testFilePath)
	if !isProtected2 {
		t.Error("Expected traditional path to be recognized as protected file")
	}

	isProtected3 := shieldedNode.isProtectedFile("invalid_sha")
	if isProtected3 {
		t.Error("Expected invalid SHA to not be recognized as protected file")
	}

	if len(shaIdentifier) != 12 {
		t.Errorf("Expected SHA identifier to be 12 characters, got %d", len(shaIdentifier))
	}

	t.Logf("SHA256 identifier: %s", shaIdentifier)
	t.Logf("Test content: %s", testContent)
}

func TestIsHexFunction(t *testing.T) {
	validCases := []struct {
		input    string
		expected bool
	}{
		{"abcdef123456", true},
		{"ABCDEF123456", true},
		{"0123456789ab", true},
		{"ffffffffffff", true},
		{"000000000000", true},
		{"abc", true},
		{"xyz", false},
		{"", false},
		{"gggggggggggg", false},
	}

	for _, tc := range validCases {
		result := isHex(tc.input)
		if result != tc.expected {
			t.Errorf("isHex(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestSHAIdentifierGeneration(t *testing.T) {
	testCases := []string{
		"test content 1",
		"another test content",
		"",
		"special chars: !@#$%^&*()",
	}

	for _, content := range testCases {
		dataHash := sha256.Sum256([]byte(content))
		shaIdentifier := fmt.Sprintf("%x", dataHash)[:12]

		if len(shaIdentifier) != 12 {
			t.Errorf("For content %q, expected SHA identifier to be 12 characters, got %d", content, len(shaIdentifier))
		}

		if !isHex(shaIdentifier) {
			t.Errorf("For content %q, generated SHA identifier is not valid hex: %s", content, shaIdentifier)
		}
	}
}
