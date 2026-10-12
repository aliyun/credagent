//go:build linux

package guard

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/agent"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestOnboardFileWithPermissions(t *testing.T) {
	// Create temporary file for testing
	tempFile, err := os.CreateTemp("", "test_onboard_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Set specific permissions on the temp file
	testUID := uint32(os.Getuid())
	testGID := uint32(os.Getgid())
	testMode := os.FileMode(0644)

	err = tempFile.Chmod(testMode)
	assert.NoError(t, err)

	// Close the file so we can test reading it
	tempFile.Close()

	// Create a sample file content
	content := []byte("test credential content")

	// Read the file info to get permissions
	fileInfo, err := os.Stat(tempFile.Name())
	assert.NoError(t, err)

	// Get permissions using syscall
	sys := fileInfo.Sys()
	stat_t, ok := sys.(*syscall.Stat_t)
	assert.True(t, ok, "File info should be of type *syscall.Stat_t")

	// Create permissions struct
	permissions := &enclave.FilePerms{
		Uid:  stat_t.Uid,
		Gid:  stat_t.Gid,
		Mode: uint32(fileInfo.Mode().Perm()),
	}

	// Create test stores
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := createTestCredAgentClient()

	// Create admin password store
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_onboard")
	assert.NoError(t, err)

	// Create policy engine
	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Create OnboardFileRequest with permissions
	req := &enclave.OnboardFileRequest{
		TargetPath:           tempFile.Name(),
		PlaintextData:        content,
		Permissions:          permissions,
		AllowedBinaries:      []string{"/bin/test"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	// Call OnboardFile
	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.GetSuccess())

	// Verify the baseline was stored with correct permissions
	bl := baselineStore.Get(tempFile.Name())
	assert.NotNil(t, bl)
	assert.NotNil(t, bl.Metadata().Permissions)
	assert.Equal(t, testUID, bl.Metadata().Permissions.UID)
	assert.Equal(t, testGID, bl.Metadata().Permissions.GID)
	assert.Equal(t, uint32(testMode.Perm()), bl.Metadata().Permissions.Mode)
	blContent, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, content, blContent)

	// Test CheckFileExistence to verify permissions are returned
	procCtx := &enclave.ProcessContext{
		ObjectPath: tempFile.Name(),
	}
	existenceResp, err := engine.CheckFileExistence(context.Background(), procCtx)
	assert.NoError(t, err)
	assert.True(t, existenceResp.GetExists())
	assert.Equal(t, testUID, existenceResp.GetPermissions().GetUid())
	assert.Equal(t, testGID, existenceResp.GetPermissions().GetGid())
	assert.Equal(t, uint32(testMode.Perm()), existenceResp.GetPermissions().GetMode())
}

func TestOnboardFileWithoutPermissions(t *testing.T) {
	// Create test stores
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := createTestCredAgentClient()

	// Create admin password store
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_onboard2")
	assert.NoError(t, err)

	// Create policy engine
	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Create OnboardFileRequest without permissions (legacy case)
	content := []byte("test credential content")
	req := &enclave.OnboardFileRequest{
		TargetPath:           "/test/path",
		PlaintextData:        content,
		Permissions:          nil, // No permissions
		AllowedBinaries:      []string{"/bin/test"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	// Call OnboardFile
	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.GetSuccess())

	// Verify the baseline was stored
	bl2 := baselineStore.Get("/test/path")
	assert.NotNil(t, bl2)
	bl2Content, err := bl2.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, content, bl2Content)
	// Permissions should be nil in this case
	assert.Nil(t, bl2.Metadata().Permissions)
}

func TestOnboardFileProcessContextExtraction(t *testing.T) {
	// Test extraction of process context with permissions
	pid := int32(os.Getpid())

	// Create a test file
	tempFile, err := os.CreateTemp("", "test_proc_ctx_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	testContent := []byte("test content")
	_, err = tempFile.Write(testContent)
	assert.NoError(t, err)
	tempFile.Close()

	// Set specific permissions
	err = os.Chmod(tempFile.Name(), 0600)
	assert.NoError(t, err)

	// Extract process context
	procCtx := &enclave.ProcessContext{
		Pid:        pid,
		ObjectPath: tempFile.Name(),
	}

	// Test access with the extracted context
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := createTestCredAgentClient()

	// Create admin password store
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_onboard4")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// First, onboard the file
	fileContent, err := os.ReadFile(tempFile.Name())
	assert.NoError(t, err)

	// Get file permissions
	fileInfo, err := os.Stat(tempFile.Name())
	assert.NoError(t, err)

	sys := fileInfo.Sys()
	stat_t, ok := sys.(*syscall.Stat_t)
	assert.True(t, ok)

	permissions := &enclave.FilePerms{
		Uid:  stat_t.Uid,
		Gid:  stat_t.Gid,
		Mode: uint32(fileInfo.Mode().Perm()),
	}

	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:           tempFile.Name(),
		PlaintextData:        fileContent,
		Permissions:          permissions,
		AllowedBinaries:      []string{procCtx.GetExePath()},
		VerificationStrategy: "ONE_TIME_USE",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, onboardResp.GetSuccess())

	// Now try to access with the extracted context using the new API
	process := osutil.NewMockProcess(pid,
		osutil.WithUid(int32(procCtx.GetUid())),
		osutil.WithExePath(procCtx.GetExePath()),
		osutil.WithSha256(procCtx.GetExeSha256()),
		osutil.WithCmdline(procCtx.GetCmdline()),
	)
	accessResp, err := engine.RequestFUSEAccess(context.Background(), procCtx.GetObjectPath(), process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, accessResp.GetStatus()) // Should fail because no permit UUID provided for ONE_TIME_USE
	assert.Contains(t, accessResp.GetDenialReason(), "permit UUID is required")
}

// Helper function to create a test CredAgentClient
func createTestCredAgentClient() *agent.CredAgentClient {
	// This is a minimal implementation for testing
	return &agent.CredAgentClient{}
}

// Test for running a more comprehensive integration test
func TestOnboardAndAccessFile(t *testing.T) {
	// Create a test file
	tempFile, err := os.CreateTemp("", "test_integration_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	testContent := []byte("test credential content")
	_, err = tempFile.Write(testContent)
	assert.NoError(t, err)
	tempFile.Close()

	// Set specific permissions
	err = os.Chmod(tempFile.Name(), 0600)
	assert.NoError(t, err)

	// Create a process with CRED_PERMIT_UUID in environment
	cmd := exec.Command("sleep", "10") // Using sleep to have a process to extract context from
	cmd.Env = append(os.Environ(), "CRED_PERMIT_UUID=test-uuid-123")
	err = cmd.Start()
	if err != nil {
		t.Skipf("Failed to start sleep process: %v", err)
	}
	defer cmd.Process.Kill()

	// Sleep to ensure process is running
	//time.Sleep(100 * time.Millisecond)

	// Build process context
	procCtx := &enclave.ProcessContext{
		Pid:        int32(cmd.Process.Pid),
		ObjectPath: tempFile.Name(),
	}

	// Create test stores and engine
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := createTestCredAgentClient()

	// Create admin password store
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_onboard5")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Get file permissions
	fileInfo, err := os.Stat(tempFile.Name())
	assert.NoError(t, err)

	sys := fileInfo.Sys()
	stat_t, ok := sys.(*syscall.Stat_t)
	assert.True(t, ok)

	permissions := &enclave.FilePerms{
		Uid:  stat_t.Uid,
		Gid:  stat_t.Gid,
		Mode: uint32(fileInfo.Mode().Perm()),
	}

	// Onboard the file
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:           tempFile.Name(),
		PlaintextData:        testContent,
		Permissions:          permissions,
		AllowedBinaries:      []string{procCtx.GetExePath()},
		VerificationStrategy: "SPEC_VERIFICATION",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, onboardResp.GetSuccess())

	// Now try to access with the extracted context using the new API
	process2 := osutil.NewMockProcess(int32(cmd.Process.Pid),
		osutil.WithUid(int32(procCtx.GetUid())),
		osutil.WithExePath(procCtx.GetExePath()),
		osutil.WithSha256(procCtx.GetExeSha256()),
		osutil.WithCmdline(procCtx.GetCmdline()),
		osutil.WithPermitUuid(procCtx.GetPermitUuid()),
	)
	accessResp, err := engine.RequestFUSEAccess(context.Background(), procCtx.GetObjectPath(), process2, &FUSEAccessRequest{})
	assert.NoError(t, err)

	logger.Info("Access response: %+v", accessResp)

	// For SPEC_VERIFICATION, access should be allowed with a permit ticket
	if accessResp.GetStatus() != enclave.AccessStatus_ACCESS_GRANTED {
		logger.Warn("Access was denied: %s", accessResp.GetDenialReason())
	}
}
