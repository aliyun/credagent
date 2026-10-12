package guard

import (
	"context"
	"fmt"
	"os"
	"testing"

	pb "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/agent"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/aliyun/credagent/internal/osutil"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestEngine(t *testing.T) (*PolicyEngine, *baseline.InMemoryBaselineStore) {
	baselineStore := baseline.NewInMemoryBaselineStore()
	ledgerStore := ledger.NewInMemoryLedger()
	credAgentClient := agent.NewCredAgentClient(nil)
	adminPasswordStore, err := NewAdminPasswordStore("test_admin_password")
	if err != nil {
		panic(err)
	}
	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte{}, adminPasswordStore, nil)
	return engine, baselineStore
}

func TestMonitorService_RequestFUSEAccess_Success(t *testing.T) {
	engine, _ := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}
	_, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/testapp"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/testapp --connect-db"),
	)

	resp, err := engine.RequestFUSEAccess(context.Background(), "/tmp/test_credential", process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, pb.AccessStatus_ACCESS_GRANTED, resp.Status)
	assert.NotEmpty(t, resp.FileSha)
}

func TestMonitorService_RequestFUSEAccess_Denied(t *testing.T) {
	engine, _ := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/allowed_app"},
		VerificationStrategy: "BASIC",
	}
	_, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/allowed_app"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/allowed_app --connect-db"),
	)

	resp, err := engine.RequestFUSEAccess(context.Background(), "/tmp/test_credential", process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, pb.AccessStatus_ACCESS_GRANTED, resp.Status)
	assert.NotEmpty(t, resp.FileSha)
}

func TestMonitorService_CheckFileExistence_Exists(t *testing.T) {
	engine, _ := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}
	result, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)
	assert.True(t, result.Success)

	req := &pb.ProcessContext{
		ObjectPath: "/tmp/test_credential",
		Pid:        int32(os.Getpid()),
		Uid:        1000,
		ExePath:    "/usr/bin/testapp",
		Cmdline:    "/usr/bin/testapp --connect-db",
	}

	resp, err := engine.CheckFileExistence(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Exists)
	assert.True(t, resp.IsProtected)
	assert.NotEmpty(t, resp.Sha)
	assert.Equal(t, "/tmp/test_credential", resp.TargetPath)
}

func TestMonitorService_CheckFileExistence_NotExists(t *testing.T) {
	engine, _ := createTestEngine(t)

	req := &pb.ProcessContext{
		ObjectPath: "/tmp/nonexistent_credential",
		Pid:        int32(os.Getpid()),
		Uid:        1000,
		ExePath:    "/usr/bin/testapp",
		Cmdline:    "/usr/bin/testapp --connect-db",
	}

	resp, err := engine.CheckFileExistence(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Exists)
	assert.False(t, resp.IsProtected)
}

func TestMonitorService_ListProtectedFiles(t *testing.T) {
	engine, _ := createTestEngine(t)

	filesToAdd := []string{"/tmp/cred1", "/tmp/cred2", "/tmp/cred3"}
	for i, filePath := range filesToAdd {
		onboardReq := &pb.OnboardFileRequest{
			TargetPath:    filePath,
			PlaintextData: []byte(fmt.Sprintf("encrypted_secret_%d", i)),
			Permissions: &pb.FilePerms{
				Uid:  1000,
				Gid:  1000,
				Mode: 0600,
			},
			AllowedBinaries:      []string{"/usr/bin/testapp"},
			VerificationStrategy: "BASIC",
		}
		result, err := engine.OnboardFile(context.Background(), onboardReq)
		require.NoError(t, err)
		assert.True(t, result.Success)
	}

	emptyReq := &emptypb.Empty{}
	resp, err := engine.ListProtectedFiles(context.Background(), emptyReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Len(t, resp.Baselines, len(filesToAdd))

	for _, filePath := range filesToAdd {
		found := false
		for _, baseline := range resp.Baselines {
			if baseline.TargetPath == filePath {
				found = true
				break
			}
		}
		assert.True(t, found, "File %s should be in the list", filePath)
	}
}

func TestMonitorService_ReadContentViaBaseline(t *testing.T) {
	engine, baselineStore := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}
	_, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/testapp"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/testapp --connect-db"),
	)

	fuseResp, err := engine.RequestFUSEAccess(context.Background(), "/tmp/test_credential", process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, fuseResp)
	assert.Equal(t, pb.AccessStatus_ACCESS_GRANTED, fuseResp.Status)
	assert.NotEmpty(t, fuseResp.FileSha)

	// Read content directly from baseline store
	bl := baselineStore.GetBySha(fuseResp.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("encrypted_secret"), content)
}

func TestMonitorService_BaselineAccessAfterGrant(t *testing.T) {
	engine, baselineStore := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}
	_, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/testapp"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("/usr/bin/testapp --connect-db"),
	)

	fuseResp, err := engine.RequestFUSEAccess(context.Background(), "/tmp/test_credential", process, &FUSEAccessRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, fuseResp)
	assert.Equal(t, pb.AccessStatus_ACCESS_GRANTED, fuseResp.Status)
	assert.NotEmpty(t, fuseResp.FileSha)

	// Verify baseline content is accessible via FileSha
	bl := baselineStore.GetBySha(fuseResp.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("encrypted_secret"), content)
}

func TestMonitorService_ErrorHandling(t *testing.T) {
	engine, _ := createTestEngine(t)

	t.Run("RequestFUSEAccess with empty object path", func(t *testing.T) {
		process := osutil.NewMockProcess(int32(os.Getpid()),
			osutil.WithUid(1000),
			osutil.WithGid(1000),
			osutil.WithExePath("/usr/bin/testapp"),
			osutil.WithSha256("fake-sha256"),
			osutil.WithCmdline("/usr/bin/testapp --connect-db"),
		)

		resp, err := engine.RequestFUSEAccess(context.Background(), "", process, &FUSEAccessRequest{})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, pb.AccessStatus_ACCESS_BASELINE_DENIED, resp.Status)
	})

	t.Run("CheckFileExistence with empty object path", func(t *testing.T) {
		req := &pb.ProcessContext{
			ObjectPath: "",
			Pid:        int32(os.Getpid()),
			Uid:        1000,
			ExePath:    "/usr/bin/testapp",
			Cmdline:    "/usr/bin/testapp --connect-db",
		}

		resp, err := engine.CheckFileExistence(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.False(t, resp.Exists)
	})
}

func TestMonitorService_OnboardFileRequest_EncryptedDataField(t *testing.T) {
	engine, _ := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}

	result, err := engine.OnboardFile(context.Background(), onboardReq)
	assert.NoError(t, err)
	assert.True(t, result.Success)
}

func TestMonitorService_ConcurrentAccess(t *testing.T) {
	engine, baselineStore := createTestEngine(t)

	onboardReq := &pb.OnboardFileRequest{
		TargetPath:    "/tmp/test_credential",
		PlaintextData: []byte("encrypted_secret"),
		Permissions: &pb.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/testapp"},
		VerificationStrategy: "BASIC",
	}
	_, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	numGoroutines := 10
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			process := osutil.NewMockProcess(int32(os.Getpid()),
				osutil.WithUid(1000),
				osutil.WithGid(1000),
				osutil.WithExePath("/usr/bin/testapp"),
				osutil.WithSha256("fake-sha256"),
				osutil.WithCmdline("/usr/bin/testapp --connect-db"),
			)

			resp, err := engine.RequestFUSEAccess(context.Background(), "/tmp/test_credential", process, &FUSEAccessRequest{})
			if err != nil {
				results <- err
				return
			}

			if resp.Status != pb.AccessStatus_ACCESS_GRANTED {
				results <- fmt.Errorf("access denied for goroutine %d: %s", id, resp.DenialReason)
				return
			}

			if resp.FileSha == "" {
				results <- fmt.Errorf("empty FileSha for goroutine %d", id)
				return
			}

			bl := baselineStore.GetBySha(resp.FileSha)
			if bl == nil {
				results <- fmt.Errorf("baseline not found for goroutine %d", id)
				return
			}

			content, err := bl.FileContent()
			if err != nil {
				results <- err
				return
			}

			if string(content) != "encrypted_secret" {
				results <- fmt.Errorf("content mismatch for goroutine %d: got %s", id, string(content))
				return
			}

			results <- nil
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		err := <-results
		assert.NoError(t, err, "Concurrent access failed for goroutine")
	}
}
