package guard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/ledger"
	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestMonitorGuardService_RequestFUSEAccess_BASIC tests the BASIC strategy through the MonitorGuardService interface
func TestMonitorGuardService_RequestFUSEAccess_BASIC(t *testing.T) {
	// Setup
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_basic"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	// Create OnboardFileRequest with BASIC strategy
	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "BASIC",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.NotEmpty(t, response.FileSha)
	assert.Equal(t, int64(0), response.MaxOpenCount)

	bl := baselineStore.GetBySha(response.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_password"), content)
}

// TestMonitorGuardService_RequestFUSEAccess_ONE_TIME_USE tests the ONE_TIME_USE strategy through the MonitorGuardService interface
func TestMonitorGuardService_RequestFUSEAccess_ONE_TIME_USE(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_one_time_use"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
		CommandSpec:    "psql -h localhost -U postgres -d mydb",
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.NotEmpty(t, response.FileSha)

	bl := baselineStore.GetBySha(response.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_password"), content)

	result := ledgerStore.ConsumeTicket("test-uuid-123", 0, "ONE_TIME_USE")
	assert.False(t, result.Success)
	assert.Equal(t, "Ticket has already been used.", result.DenialReason)
}

// TestMonitorGuardService_RequestFUSEAccess_PID_BIND_FirstAccess tests the PID_BIND strategy first access
func TestMonitorGuardService_RequestFUSEAccess_PID_BIND_FirstAccess(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_pid_bind_first"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "PID_BIND",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
		CommandSpec:    "psql -h localhost -U postgres -d mydb",
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.NotEmpty(t, response.FileSha)

	bl := baselineStore.GetBySha(response.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_password"), content)
}

// TestMonitorGuardService_RequestFUSEAccess_PID_BIND_SubsequentAccess tests the PID_BIND strategy subsequent access
func TestMonitorGuardService_RequestFUSEAccess_PID_BIND_SubsequentAccess(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_pid_bind_subsequent"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "PID_BIND",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "ACTIVE",
		BoundPid:       int64(os.Getpid()),
		CommandSpec:    "psql -h localhost -U postgres -d mydb",
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.NotEmpty(t, response.FileSha)

	bl := baselineStore.GetBySha(response.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_password"), content)
}

// TestMonitorGuardService_RequestFUSEAccess_PID_BIND_TOCTOU_Detection tests the PID_BIND strategy TOCTOU detection
func TestMonitorGuardService_RequestFUSEAccess_PID_BIND_TOCTOU_Detection(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_pid_bind_toctou"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "PID_BIND",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "ACTIVE",
		BoundPid:       int64(os.Getpid()),
		CommandSpec:    "psql -h localhost -U postgres -d mydb",
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	// Spawn a helper process to get a different real PID
	helperCmd := exec.Command("sleep", "10")
	err = helperCmd.Start()
	require.NoError(t, err)
	defer helperCmd.Process.Kill()

	// Different PID - potential TOCTOU attack
	process := osutil.NewMockProcess(int32(helperCmd.Process.Pid),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, response.Status)
	assert.Contains(t, response.DenialReason, "TOCTOU attack detected")
	assert.Contains(t, response.DenialReason, "Ticket has been burned")
}

// TestMonitorGuardService_RequestFUSEAccess_SPEC_VERIFICATION tests the SPEC_VERIFICATION strategy
func TestMonitorGuardService_RequestFUSEAccess_SPEC_VERIFICATION(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_spec_verification"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/aliyun/config.json",
		PlaintextData: []byte("secret_config"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/aliyun"},
		VerificationStrategy: "SPEC_VERIFICATION",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/aliyun"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("aliyun oss ls"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/aliyun/config.json", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.NotEmpty(t, response.FileSha)

	bl := baselineStore.GetBySha(response.FileSha)
	assert.NotNil(t, bl)
	content, err := bl.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_config"), content)
}

// TestMonitorGuardService_RequestFUSEAccess_BaselineNotFound tests baseline not found scenario
func TestMonitorGuardService_RequestFUSEAccess_BaselineNotFound(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_baseline_not_found"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/nonexistent/path", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_BASELINE_DENIED, response.Status)
	assert.Equal(t, "No baseline found for the requested object.", response.DenialReason)
}

// TestMonitorGuardService_RequestFUSEAccess_NoPermitTicket tests scenarios where no permit ticket is provided but required
func TestMonitorGuardService_RequestFUSEAccess_NoPermitTicket(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_no_permit_ticket"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "ONE_TIME_USE",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// No UUID provided but required for ONE_TIME_USE
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, response.Status)
	assert.Contains(t, response.DenialReason, "A valid permit UUID is required for this strategy")
}

// TestMonitorGuardService_CheckFileExistence tests the CheckFileExistence method
func TestMonitorGuardService_CheckFileExistence(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_check_existence"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	req := &enclave.OnboardFileRequest{
		TargetPath:    "/etc/psql/passwd",
		PlaintextData: []byte("secret_password"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/usr/bin/psql"},
		VerificationStrategy: "BASIC",
	}

	resp, err := engine.OnboardFile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	procCtx := &enclave.ProcessContext{
		Pid:        int32(os.Getpid()),
		Uid:        1000,
		ExePath:    "/usr/bin/psql",
		Cmdline:    "psql -h localhost -U postgres -d mydb",
		PermitUuid: "",
		ObjectPath: "/etc/psql/passwd",
	}

	response, err := engine.CheckFileExistence(context.Background(), procCtx)

	assert.NoError(t, err)
	assert.True(t, response.Exists)
	assert.True(t, response.IsProtected)
	assert.NotEmpty(t, response.Sha)
	assert.Equal(t, "/etc/psql/passwd", response.TargetPath)
	assert.Equal(t, req.Permissions.Uid, response.Permissions.Uid)
	assert.Equal(t, req.Permissions.Gid, response.Permissions.Gid)
	assert.Equal(t, req.Permissions.Mode, response.Permissions.Mode)
}

// TestMonitorGuardService_CheckFileExistence_NotFound tests the CheckFileExistence method when file doesn't exist
func TestMonitorGuardService_CheckFileExistence_NotFound(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore(filepath.Join(t.TempDir(), "admin_password_check_existence_not_found"))
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	procCtx := &enclave.ProcessContext{
		Pid:        int32(os.Getpid()),
		Uid:        1000,
		ExePath:    "/usr/bin/psql",
		Cmdline:    "psql -h localhost -U postgres -d mydb",
		PermitUuid: "",
		ObjectPath: "/nonexistent/path",
	}

	response, err := engine.CheckFileExistence(context.Background(), procCtx)

	assert.NoError(t, err)
	assert.False(t, response.Exists)
	assert.False(t, response.IsProtected)
	assert.Empty(t, response.Sha)
	assert.Empty(t, response.TargetPath)
	assert.Nil(t, response.Permissions)
}
