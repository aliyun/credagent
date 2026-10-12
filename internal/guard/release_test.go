package guard

import (
	"context"
	"os"
	"testing"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestReleaseFile tests the ReleaseFile functionality with password validation only
func TestReleaseFile(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test_release_*")
	assert.NoError(t, err)
	tempFileName := tempFile.Name()
	defer os.Remove(tempFileName)
	tempFile.Close()

	// Create a baseline store and add a test baseline
	baselineStore := baseline.NewInMemoryBaselineStore()
	testBaseline := baseline.NewCredentialBaseline(
		"abc123",
		baseline.FileMetadata{
			TargetPath:  tempFileName,
			Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0600},
		},
		&baseline.AccessRule{},
		[]byte("test-data"),
	)
	err = baselineStore.Save(testBaseline)
	assert.NoError(t, err)

	// Create a mock CredAgentClient using the existing one from basic_strategy_test.go
	mockCredAgent := &MockCredAgentClient{}

	// Create ledger store
	ledgerStore := ledger.NewInMemoryLedger()

	// Create PolicyEngine
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_release") // Create a default password store for testing
	assert.NoError(t, err)

	// Set a test password
	err = adminPasswordStore.SetPassword("correct-password")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, mockCredAgent, []byte("test-key-32-byte-for-aes-testing"), adminPasswordStore, nil)

	t.Run("should succeed when correct password is provided regardless of UID", func(t *testing.T) {
		// Re-add the baseline since it might have been deleted in other tests
		err = baselineStore.Save(testBaseline)
		assert.NoError(t, err)

		// Create ReleaseFileRequest with SHA identifier and correct password
		req := &enclave.ReleaseFileRequest{
			FileId:   "abc123",           // SHA identifier of the baseline
			Uid:      1001,               // Different UID, should not matter anymore
			Password: "correct-password", // Correct password
		}

		// Call ReleaseFile
		resp, err := engine.ReleaseFile(context.Background(), req)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "File release data retrieved successfully", resp.Message)

		// Check that the baseline was NOT deleted (it's deleted later in credctl)
		remainingBaseline := baselineStore.Get(tempFileName)
		assert.NotNil(t, remainingBaseline)

		// Check that the returned data is valid
		assert.Equal(t, []byte("test-data"), resp.FileContent)
		assert.Equal(t, uint32(1000), resp.OwnerUid)
		assert.Equal(t, uint32(1000), resp.OwnerGid)
		assert.Equal(t, uint32(0600), resp.Permission)
		assert.Equal(t, tempFileName, resp.FilePath)
	})

	t.Run("should fail when incorrect password is provided", func(t *testing.T) {
		// Re-add the baseline since it was deleted in the previous test
		err = baselineStore.Save(testBaseline)
		assert.NoError(t, err)

		// Create ReleaseFileRequest with wrong password
		req := &enclave.ReleaseFileRequest{
			FileId:   "abc123",         // SHA identifier of the baseline
			Uid:      1000,             // Any UID
			Password: "wrong-password", // Wrong password
		}

		// Call ReleaseFile - expect an error with PermissionDenied status
		resp, err := engine.ReleaseFile(context.Background(), req)

		// Check that we got a gRPC error with PermissionDenied code
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, s.Code())

		// Response should be nil when there's an error
		assert.Nil(t, resp)

		// Check that the baseline was NOT deleted
		stillExistsBaseline := baselineStore.Get(tempFileName)
		assert.NotNil(t, stillExistsBaseline)
	})

	t.Run("should fail when password is required but not provided", func(t *testing.T) {
		// Re-add the baseline since it was deleted in the previous test
		err = baselineStore.Save(testBaseline)
		assert.NoError(t, err)

		// Create ReleaseFileRequest with no password
		req := &enclave.ReleaseFileRequest{
			FileId:   "abc123", // SHA identifier of the baseline
			Uid:      1000,     // Any UID
			Password: "",       // Missing password
		}

		// Call ReleaseFile - expect an error with InvalidArgument status
		resp, err := engine.ReleaseFile(context.Background(), req)

		// Check that we got a gRPC error with InvalidArgument code
		s, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, s.Code())

		// Response should be nil when there's an error
		assert.Nil(t, resp)

		// Check that the baseline was NOT deleted
		stillExistsBaseline := baselineStore.Get(tempFileName)
		assert.NotNil(t, stillExistsBaseline)
	})
}
