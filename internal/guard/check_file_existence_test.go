package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/ledger"
	"github.com/alibaba/CredAgent/pkg/logger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCheckFileExistence(t *testing.T) {
	// Set up test environment
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := agent.NewCredAgentClient(nil) // nil config for testing
	masterKey := make([]byte, 32)                    // dummy key for testing

	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_check_exist")
	assert.NoError(t, err)
	policyEngine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	// Test data
	testFilePath := "/test/credential"
	testData := []byte("This is a test credential")

	// Calculate SHA256 of the test data to use as the file identifier
	dataHash := sha256.Sum256(testData)
	shaIdentifier := hex.EncodeToString(dataHash[:])[:12]

	// 1. Test when file does not exist in baseline
	t.Run("FileNotInBaseline", func(t *testing.T) {
		procCtx := &enclave.ProcessContext{
			ObjectPath: "/nonexistent/path",
		}

		response, err := policyEngine.CheckFileExistence(context.Background(), procCtx)
		assert.NoError(t, err)
		assert.False(t, response.Exists)
		assert.False(t, response.IsProtected)
		assert.Equal(t, "", response.Sha)
		assert.Equal(t, "", response.TargetPath)
		assert.Nil(t, response.Permissions)
		assert.Equal(t, "No baseline found for the requested object.", response.DenialReason)
	})

	// 2. Test when file exists in baseline (using target path)
	t.Run("FileExistsInBaselineByTargetPath", func(t *testing.T) {
		// Create a baseline entry
		baselineEntry := baseline.NewCredentialBaseline(
			shaIdentifier,
			baseline.FileMetadata{
				TargetPath:  testFilePath,
				Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0600},
				Ctime:       timestamppb.Now(),
				Size:        int64(len(testData)),
			},
			&baseline.AccessRule{
				AllowedPrograms:      []string{"/bin/cat"},
				VerificationStrategy: "SPEC_VERIFICATION",
			},
			testData,
		)

		err := baselineStore.Save(baselineEntry)
		assert.NoError(t, err)

		procCtx := &enclave.ProcessContext{
			ObjectPath: testFilePath, // Using target path
		}

		response, err := policyEngine.CheckFileExistence(context.Background(), procCtx)
		assert.NoError(t, err)
		assert.True(t, response.Exists)
		assert.True(t, response.IsProtected)
		assert.Equal(t, shaIdentifier, response.Sha)
		assert.Equal(t, testFilePath, response.TargetPath)
		assert.NotNil(t, response.Permissions)
		assert.Equal(t, uint32(1000), response.Permissions.Uid)
		assert.Equal(t, uint32(1000), response.Permissions.Gid)
		assert.Equal(t, uint32(0600), response.Permissions.Mode)
		assert.Equal(t, "", response.DenialReason)
	})

	// 3. Test when file exists in baseline (using SHA identifier)
	t.Run("FileExistsInBaselineBySHA", func(t *testing.T) {
		procCtx := &enclave.ProcessContext{
			ObjectPath: shaIdentifier, // Using SHA identifier
		}

		response, err := policyEngine.CheckFileExistence(context.Background(), procCtx)
		assert.NoError(t, err)
		assert.True(t, response.Exists)
		assert.True(t, response.IsProtected)
		assert.Equal(t, shaIdentifier, response.Sha)
		assert.Equal(t, testFilePath, response.TargetPath)
		assert.NotNil(t, response.Permissions)
		assert.Equal(t, uint32(1000), response.Permissions.Uid)
		assert.Equal(t, uint32(1000), response.Permissions.Gid)
		assert.Equal(t, uint32(0600), response.Permissions.Mode)
		assert.Equal(t, "", response.DenialReason)
	})

	logger.Info("All CheckFileExistence tests passed!")
}
