package guard

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/ledger"
	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func loadTestConfig() (*agent.Config, error) {
	data, err := os.ReadFile("config.test.json")
	if err != nil {
		data, err = os.ReadFile("../agent/config.test.json")
		if err != nil {
			return &agent.Config{
				Provider:   "openai",
				APIURL:     "http://test.example.com",
				APIKey:     "test-key",
				ModelName:  "test-model",
				TimeoutSec: 30,
			}, nil
		}
	}

	var config struct {
		CredAgent struct {
			APIURL     string `json:"api_url"`
			APIKey     string `json:"api_key"`
			ModelName  string `json:"model_name"`
			TimeoutSec int    `json:"timeout_seconds"`
		} `json:"credagent"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &agent.Config{
		Provider:   "openai",
		APIURL:     config.CredAgent.APIURL,
		APIKey:     config.CredAgent.APIKey,
		ModelName:  config.CredAgent.ModelName,
		TimeoutSec: config.CredAgent.TimeoutSec,
	}, nil
}

func TestPolicyEngine_ONE_TIME_USE_Success(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_one_time_use_success")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

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

func TestPolicyEngine_PID_BIND_Success(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("this-is-a-test-master-key-for-demo-purposes-only")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_pid_bind_success")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

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

	// Second access with same PID should succeed for PID_BIND
	process2 := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	responseSecond, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process2, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_GRANTED, responseSecond.Status)
	assert.NotEmpty(t, responseSecond.FileSha)

	blSecond := baselineStore.GetBySha(responseSecond.FileSha)
	assert.NotNil(t, blSecond)
	contentSecond, err := blSecond.FileContent()
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret_password"), contentSecond)
}

func TestPolicyEngine_PID_BIND_ReuseSuccess(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("this-is-a-test-master-key-for-demo-purposes-only")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_pid_bind_reuse_success")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

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

func TestPolicyEngine_PID_BIND_TOCTOU_Failure(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("this-is-a-test-master-key-for-demo-purposes-only")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_pid_bind_toctou_failure")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

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
	assert.NoError(t, err)
	defer helperCmd.Process.Kill()
	differentPid := int32(helperCmd.Process.Pid)

	// Create access request with different PID (TOCTOU attack)
	process := osutil.NewMockProcess(differentPid,
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, response.Status)
	assert.Contains(t, response.DenialReason, "TOCTOU attack detected")
	assert.Contains(t, response.DenialReason, "Ticket has been burned")

	// Access with original PID should also fail after hijack attempt
	processOriginal := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h localhost -U postgres -d mydb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	responseAfterHijack, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", processOriginal, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.Equal(t, enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET, responseAfterHijack.Status)
	assert.Contains(t, responseAfterHijack.DenialReason, "Ticket has been burned")
	assert.NotContains(t, responseAfterHijack.DenialReason, "TOCTOU attack detected")
}

func TestPolicyEngine_ReleaseFile_Success(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_release_file_success")
	assert.NoError(t, err)

	err = adminPasswordStore.SetPassword("testpassword")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	tempFile, err := ioutil.TempFile("", "psql_passwd_test")
	assert.NoError(t, err)
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	err = tempFile.Close()
	assert.NoError(t, err)

	req := &enclave.OnboardFileRequest{
		TargetPath:    tempPath,
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: tempPath,
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

	response, err := engine.RequestFUSEAccess(context.Background(), tempPath, process, &FUSEAccessRequest{})

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

	storedBaseline := baselineStore.Get(tempPath)
	assert.NotNil(t, storedBaseline)

	releaseReq := &enclave.ReleaseFileRequest{
		FileId:   storedBaseline.SHA(),
		Password: "testpassword",
	}

	releaseResp, err := engine.ReleaseFile(context.Background(), releaseReq)
	assert.NoError(t, err)
	assert.True(t, releaseResp.Success)
	assert.Equal(t, "File release data retrieved successfully", releaseResp.Message)

	_, err = os.Stat(tempPath)
	assert.NoError(t, err)

	assert.NotNil(t, baselineStore.Get(tempPath))
}

func TestPolicyEngine_BaselineNotFound(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_baseline_not_found")
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
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Equal(t, "No baseline found for the requested object.", response.DenialReason)
}

func TestPolicyEngine_BinaryNotAllowed(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_binary_not_allowed")
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

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/unauthorized"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("unauthorized -h localhost"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Contains(t, response.DenialReason, "Ticket not found")
}

func TestPolicyEngine_SpecVerificationWithoutUUID(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_spec_verification_without_uuid")
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

func TestPolicyEngine_UnknownStrategy(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("test-key")
	config, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(config)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_unknown_strategy")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminPasswordStore, nil)

	testBaseline := baseline.NewCredentialBaseline(
		"abc123def456",
		baseline.FileMetadata{
			TargetPath:  "/etc/unknown/config",
			Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0600},
		},
		&baseline.AccessRule{
			VerificationStrategy: "UNKNOWN_STRATEGY",
			AllowedPrograms:      []string{"/usr/bin/tool"},
		},
		[]byte("secret_data"),
	)
	err = baselineStore.Save(testBaseline)
	assert.NoError(t, err)

	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/tool"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("tool --config"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/unknown/config", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Equal(t, "Unknown verification strategy in baseline.", response.DenialReason)
}

func TestPolicyEngine_CommandSpecMismatch(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("this-is-a-test-master-key-for-demo-purposes-only")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_command_spec_mismatch")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
		CommandSpec:    "psql -h localhost -U postgres -d mydb",
		ExpiresAt:      timestamppb.New(time.Now().Add(5 * time.Minute)),
	}
	ledgerStore.AddTicket(ticket)

	// Different command (mismatch)
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/psql"),
		osutil.WithSha256("fake-sha256"),
		osutil.WithCmdline("psql -h remotehost -U admin -d otherdb"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	response, err := engine.RequestFUSEAccess(context.Background(), "/etc/psql/passwd", process, &FUSEAccessRequest{})

	assert.NoError(t, err)
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Contains(t, response.DenialReason, "Command spec mismatch")
}

func TestPolicyEngine_CommandSpecEmpty(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	masterKey := []byte("this-is-a-test-master-key-for-demo-purposes-only")
	agentConfig, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	credAgentClient := agent.NewCredAgentClient(agentConfig)
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_engine_command_spec_empty")
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
	assert.Equal(t, "File onboarded successfully", resp.Message)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
		CommandSpec:    "",
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
	assert.NotEqual(t, enclave.AccessStatus_ACCESS_GRANTED, response.Status)
	assert.Contains(t, response.DenialReason, "Command spec is empty")
}

func getCallerUID(ctx context.Context) int32 {
	return 0
}

func getFileOwner(targetPath string) int32 {
	return 1000
}
