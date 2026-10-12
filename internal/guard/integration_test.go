package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/aliyun/credagent/internal/osutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestCredMonCredAgentIntegration tests the interaction between credmon (via MonitorGuardService)
// and credagent (via EnclaveGuardService) components
func TestCredMonCredAgentIntegration(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key-for-integration")

	credAgentClient := NewMockCredAgentClient(true)

	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_integration")
	assert.NoError(t, err)
	err = adminPasswordStore.SetPassword("testpassword")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	tempFile, err := ioutil.TempFile("", "integration_test_*")
	assert.NoError(t, err)
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	err = tempFile.Close()
	assert.NoError(t, err)

	testContent := []byte("test secret content for integration test")
	err = ioutil.WriteFile(tempPath, testContent, 0600)
	assert.NoError(t, err)

	// Step 1: Onboard a file
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    tempPath,
		PlaintextData: testContent,
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/test-binary"},
		VerificationStrategy: "SPEC_VERIFICATION",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, onboardResp.Success)
	assert.Equal(t, "File onboarded successfully", onboardResp.Message)

	baselines := baselineStore.ListAll()
	assert.Len(t, baselines, 1)
	bl := baselines[0]
	assert.Equal(t, tempPath, bl.Metadata().TargetPath)
	blContent, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, string(testContent), string(blContent))

	expectedSha := calculateSHA256ForPath(tempPath)
	assert.Equal(t, expectedSha[:12], bl.SHA())

	// Step 2: Request permission
	permissionReq := &enclave.RequestPermissionRequest{
		Intent:     "Testing access to credential file",
		Cmdline:    "/usr/bin/test-binary --config " + tempPath,
		TargetFile: tempPath,
	}

	permissionResp, err := engine.RequestPermission(context.Background(), permissionReq)
	assert.NoError(t, err)
	assert.True(t, permissionResp.Success)
	assert.Equal(t, "ALLOW", permissionResp.Decision)
	assert.NotEmpty(t, permissionResp.Uuid)

	ticket, exists := ledgerStore.GetTicket(permissionResp.Uuid)
	assert.True(t, exists)
	assert.Equal(t, tempPath, ticket.GetTargetFilePath())
	assert.Equal(t, "ACTIVE", ticket.GetStatus())

	// Step 3: Request FUSE access
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid(permissionResp.Uuid),
	)

	accessResp, err := engine.RequestFUSEAccess(context.Background(), bl.SHA(), process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, accessResp.Status)
	assert.NotEmpty(t, accessResp.GetFileSha())
	assert.Equal(t, bl.SHA(), accessResp.GetFileSha())

	// Step 4: Read content directly from baseline store using FileSha
	readBl := baselineStore.GetBySha(accessResp.GetFileSha())
	assert.NotNil(t, readBl)
	readContent, err := readBl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, testContent, readContent)

	// Step 5: Verify partial read works at the byte level
	expectedPartial := testContent[5:15]
	assert.Equal(t, expectedPartial, readContent[5:15])

	// Step 6: Test releasing the file
	releaseReq := &enclave.ReleaseFileRequest{
		FileId:   bl.SHA(),
		Password: "testpassword",
		Uid:      0,
	}

	releaseResp, err := engine.ReleaseFile(context.Background(), releaseReq)
	assert.NoError(t, err)
	assert.True(t, releaseResp.Success)
	assert.Equal(t, "File release data retrieved successfully", releaseResp.Message)
	assert.Equal(t, tempPath, releaseResp.FilePath)
	assert.Equal(t, testContent, releaseResp.FileContent)
	assert.Equal(t, uint32(1000), releaseResp.OwnerUid)
	assert.Equal(t, uint32(1000), releaseResp.OwnerGid)
	assert.Equal(t, uint32(0600), releaseResp.Permission)
	assert.Equal(t, bl.SHA(), releaseResp.FileId)

	// Step 7: Test that the baseline still exists
	storedBaseline := baselineStore.Get(tempPath)
	assert.NotNil(t, storedBaseline)

	// Step 8: Test removing the baseline
	removeReq := &enclave.RemoveFileRequest{
		Sha:      bl.SHA(),
		Password: "testpassword",
	}

	removeResp, err := engine.RemoveFile(context.Background(), removeReq)
	assert.NoError(t, err)
	assert.True(t, removeResp.Success)

	removedBaseline := baselineStore.Get(tempPath)
	assert.Nil(t, removedBaseline)
}

// TestCredMonCredAgentIntegrationWithOTU tests the interaction with ONE_TIME_USE strategy
func TestCredMonCredAgentIntegrationWithOTU(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key-for-otu-integration")

	credAgentClient := NewMockCredAgentClient(true)

	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_otu_integration")
	assert.NoError(t, err)
	err = adminPasswordStore.SetPassword("testpassword")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	tempFile, err := ioutil.TempFile("", "integration_test_otu_*")
	assert.NoError(t, err)
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	err = tempFile.Close()
	assert.NoError(t, err)

	testContent := []byte("test secret content for OTU integration test")
	err = ioutil.WriteFile(tempPath, testContent, 0600)
	assert.NoError(t, err)

	// Step 1: Onboard a file with ONE_TIME_USE strategy
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    tempPath,
		PlaintextData: testContent,
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/test-binary"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, onboardResp.Success)

	bl2 := baselineStore.Get(tempPath)
	assert.NotNil(t, bl2)
	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-otu",
		TargetFilePath: tempPath,
		Status:         "PENDING",
		CommandSpec:    "/usr/bin/test-binary --config " + tempPath,
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	// Step 2: Request FUSE access
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid("test-uuid-otu"),
	)

	// First access should succeed
	accessResp, err := engine.RequestFUSEAccess(context.Background(), bl2.SHA(), process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, accessResp.Status)
	assert.NotEmpty(t, accessResp.GetFileSha())

	readBl := baselineStore.GetBySha(accessResp.GetFileSha())
	assert.NotNil(t, readBl)
	readContent, err := readBl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, testContent, readContent)

	// Step 3: Try to access again with the same ticket (should fail for ONE_TIME_USE)
	process2 := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid("test-uuid-otu"),
	)

	secondAccessResp, err := engine.RequestFUSEAccess(context.Background(), bl2.SHA(), process2, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, secondAccessResp.Status)

	burnedTicket, exists := ledgerStore.GetTicket("test-uuid-otu")
	assert.True(t, exists)
	assert.Equal(t, "BURNED", burnedTicket.GetStatus())
}

// TestCredMonCredAgentIntegrationWithPIDBind tests the interaction with PID_BIND strategy
func TestCredMonCredAgentIntegrationWithPIDBind(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key-for-pidbind-integration")

	credAgentClient := NewMockCredAgentClient(true)

	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_pidbind_integration")
	assert.NoError(t, err)
	err = adminPasswordStore.SetPassword("testpassword")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	tempFile, err := ioutil.TempFile("", "integration_test_pidbind_*")
	assert.NoError(t, err)
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	err = tempFile.Close()
	assert.NoError(t, err)

	testContent := []byte("test secret content for PID_BIND integration test")
	err = ioutil.WriteFile(tempPath, testContent, 0600)
	assert.NoError(t, err)

	// Step 1: Onboard a file with PID_BIND strategy
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    tempPath,
		PlaintextData: testContent,
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/test-binary"},
		VerificationStrategy: "PID_BIND",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, onboardResp.Success)

	bl3 := baselineStore.Get(tempPath)
	assert.NotNil(t, bl3)

	ticket2 := &enclave.PermitTicket{
		Uuid:           "test-uuid-pidbind",
		TargetFilePath: tempPath,
		Status:         "PENDING",
		CommandSpec:    "/usr/bin/test-binary --config " + tempPath,
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket2)

	// Step 2: Request FUSE access
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid("test-uuid-pidbind"),
	)

	// First access should succeed
	accessResp2, err := engine.RequestFUSEAccess(context.Background(), bl3.SHA(), process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, accessResp2.Status)
	assert.NotEmpty(t, accessResp2.GetFileSha())

	readBl2 := baselineStore.GetBySha(accessResp2.GetFileSha())
	assert.NotNil(t, readBl2)
	readContent2, err := readBl2.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, testContent, readContent2)

	// Step 3: Try to access again with the same PID (should succeed for PID_BIND)
	process2 := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid("test-uuid-pidbind"),
	)

	secondAccessResp2, err := engine.RequestFUSEAccess(context.Background(), bl3.SHA(), process2, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, secondAccessResp2.Status)

	// Spawn a helper process to get a different real PID
	helperCmd := exec.Command("sleep", "10")
	err = helperCmd.Start()
	assert.NoError(t, err)
	defer helperCmd.Process.Kill()

	// Step 4: Try to access with a different PID (should fail and burn the ticket)
	process3 := osutil.NewMockProcess(int32(helperCmd.Process.Pid),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/test-binary --config "+tempPath),
		osutil.WithPermitUuid("test-uuid-pidbind"),
	)

	thirdAccessResp, err := engine.RequestFUSEAccess(context.Background(), bl3.SHA(), process3, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, thirdAccessResp.Status)
	assert.Contains(t, thirdAccessResp.DenialReason, "TOCTOU attack detected")

	burnedTicket, exists := ledgerStore.GetTicket("test-uuid-pidbind")
	assert.True(t, exists)
	assert.Equal(t, "BURNED", burnedTicket.GetStatus())
}

// calculateSHA256ForPath calculates the SHA256 of a file path string (not content)
func calculateSHA256ForPath(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}
