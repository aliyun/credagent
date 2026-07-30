package guard

import (
	"context"
	"testing"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/ledger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ===================== RemoveFile Tests =====================

func TestRemoveFile_Success(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	// Set password first
	err = adminPasswordStore.SetPassword("testpassword")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// First onboard a file
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    "/test/remove/file.txt",
		PlaintextData: []byte("test content"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/bin/test"},
		VerificationStrategy: "BASIC",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)
	require.True(t, onboardResp.Success)

	sha := onboardResp.Sha

	// Verify baseline exists
	baseline := baselineStore.GetBySha(sha)
	require.NotNil(t, baseline)

	// Now remove the file
	removeReq := &enclave.RemoveFileRequest{
		Sha:      sha,
		Password: "testpassword",
	}

	removeResp, err := engine.RemoveFile(context.Background(), removeReq)
	assert.NoError(t, err)
	assert.True(t, removeResp.Success)

	// Verify baseline is removed
	baseline = baselineStore.GetBySha(sha)
	assert.Nil(t, baseline)
}

func TestRemoveFile_NotFound(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	err = adminPasswordStore.SetPassword("testpassword")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	removeReq := &enclave.RemoveFileRequest{
		Sha:      "nonexistent-sha",
		Password: "testpassword",
	}

	removeResp, err := engine.RemoveFile(context.Background(), removeReq)
	assert.NoError(t, err)
	assert.False(t, removeResp.Success)
	assert.Contains(t, removeResp.Message, "not found")
}

func TestRemoveFile_InvalidPassword(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	err = adminPasswordStore.SetPassword("correctpassword")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Onboard a file first
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    "/test/remove/file2.txt",
		PlaintextData: []byte("test content"),
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/bin/test"},
		VerificationStrategy: "BASIC",
	}

	onboardResp, err := engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	// Try to remove with wrong password
	removeReq := &enclave.RemoveFileRequest{
		Sha:      onboardResp.Sha,
		Password: "wrongpassword",
	}

	removeResp, err := engine.RemoveFile(context.Background(), removeReq)
	assert.NoError(t, err)
	assert.False(t, removeResp.Success)
	assert.Contains(t, removeResp.Message, "Invalid password")

	// Verify baseline still exists
	baseline := baselineStore.GetBySha(onboardResp.Sha)
	assert.NotNil(t, baseline)
}

// ===================== ListProtectedFiles Tests =====================

func TestListProtectedFiles_Empty(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	resp, err := engine.ListProtectedFiles(context.Background(), &emptypb.Empty{})
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Empty(t, resp.Baselines)
}

func TestListProtectedFiles_MultipleFiles(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Onboard multiple files
	files := []struct {
		path    string
		content []byte
	}{
		{"/etc/psql/passwd", []byte("password1")},
		{"/etc/aliyun/config.json", []byte("config1")},
		{"/home/user/.ssh/id_rsa", []byte("private_key")},
	}

	for _, f := range files {
		onboardReq := &enclave.OnboardFileRequest{
			TargetPath:    f.path,
			PlaintextData: f.content,
			Permissions: &enclave.FilePerms{
				Uid:  1000,
				Gid:  1000,
				Mode: 0600,
			},
			AllowedBinaries:      []string{"/bin/test"},
			VerificationStrategy: "BASIC",
		}
		_, err := engine.OnboardFile(context.Background(), onboardReq)
		require.NoError(t, err)
	}

	resp, err := engine.ListProtectedFiles(context.Background(), &emptypb.Empty{})
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Len(t, resp.Baselines, 3)

	// Verify each baseline contains correct metadata
	for _, b := range resp.Baselines {
		// Verify EncryptedData is NOT returned (security requirement)
		assert.Nil(t, b.EncryptedData, "EncryptedData must not be returned for security")

		// Verify other metadata is present
		assert.NotEmpty(t, b.TargetPath)
		assert.NotEmpty(t, b.Sha)
		assert.NotNil(t, b.Permissions)
		assert.NotEmpty(t, b.VerificationStrategy)
	}
}

func TestListProtectedFiles_NoSensitiveData(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Onboard a file with sensitive content
	sensitiveContent := []byte("SUPER_SECRET_PASSWORD_12345")
	onboardReq := &enclave.OnboardFileRequest{
		TargetPath:    "/secret/password.txt",
		PlaintextData: sensitiveContent,
		Permissions: &enclave.FilePerms{
			Uid:  1000,
			Gid:  1000,
			Mode: 0600,
		},
		AllowedBinaries:      []string{"/bin/app"},
		VerificationStrategy: "BASIC",
	}
	_, err = engine.OnboardFile(context.Background(), onboardReq)
	require.NoError(t, err)

	resp, err := engine.ListProtectedFiles(context.Background(), &emptypb.Empty{})
	assert.NoError(t, err)
	assert.Len(t, resp.Baselines, 1)

	// Critical security check: EncryptedData must be nil
	baseline := resp.Baselines[0]
	assert.Nil(t, baseline.EncryptedData, "SECURITY: EncryptedData must NEVER be returned in ListProtectedFiles")
	assert.Equal(t, "/secret/password.txt", baseline.TargetPath)
}

// ===================== generateUniqueSha Tests =====================

func TestGenerateUniqueSha_NoConflict(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	baseSha := "abc123def456"
	result := engine.generateUniqueSha(baseSha)
	assert.Equal(t, baseSha, result)
}

func TestGenerateUniqueSha_WithConflict(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	// Pre-create a baseline with the conflicting SHA
	existingBaseline := baseline.NewCredentialBaseline(
		"abc123def456",
		baseline.FileMetadata{TargetPath: "/existing/path"},
		&baseline.AccessRule{},
		[]byte("existing"),
	)
	err = baselineStore.Save(existingBaseline)
	require.NoError(t, err)

	// Generate unique SHA should add suffix
	result := engine.generateUniqueSha("abc123def456")
	assert.NotEqual(t, "abc123def456", result)
	assert.Contains(t, result, "abc123")
}

func TestGenerateUniqueSha_MultipleConflicts(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	baseSha := "testsha123"

	// Create multiple existing baselines with conflicting SHAs
	for i := 1; i <= 5; i++ {
		existingSha := baseSha + "-" + string(rune('0'+i))
		// For first conflict, use base SHA
		if i == 1 {
			existingSha = baseSha
		}
		existingBL := baseline.NewCredentialBaseline(
			existingSha,
			baseline.FileMetadata{TargetPath: "/existing/path" + string(rune(i))},
			&baseline.AccessRule{},
			[]byte("existing"),
		)
		err = baselineStore.Save(existingBL)
		require.NoError(t, err)
	}

	// Generate unique SHA should find a non-conflicting suffix
	result := engine.generateUniqueSha(baseSha)
	assert.NotEqual(t, baseSha, result)

	// Verify the result doesn't conflict with existing SHAs
	conflictBaseline := baselineStore.GetBySha(result)
	assert.Nil(t, conflictBaseline)
}

// ===================== checkPermissionsWithAccessMode Tests =====================

func TestCheckPermissionsWithAccessMode_OwnerRead(t *testing.T) {
	perms := &enclave.FilePerms{
		Uid:  1000,
		Gid:  1000,
		Mode: 0600, // Owner read/write only
	}

	// Owner can read
	assert.True(t, checkPermissionsWithAccessMode(1000, 1000, perms, enclave.AccessMode_READ_ONLY))

	// Owner can write
	assert.True(t, checkPermissionsWithAccessMode(1000, 1000, perms, enclave.AccessMode_WRITE_ONLY))

	// Owner can read-write
	assert.True(t, checkPermissionsWithAccessMode(1000, 1000, perms, enclave.AccessMode_READ_WRITE))

	// Non-owner cannot read
	assert.False(t, checkPermissionsWithAccessMode(2000, 1000, perms, enclave.AccessMode_READ_ONLY))

	// Non-owner cannot write
	assert.False(t, checkPermissionsWithAccessMode(2000, 1000, perms, enclave.AccessMode_WRITE_ONLY))
}

func TestCheckPermissionsWithAccessMode_GroupRead(t *testing.T) {
	perms := &enclave.FilePerms{
		Uid:  1000,
		Gid:  1000,
		Mode: 0640, // Owner read/write, group read
	}

	// Owner can read and write
	assert.True(t, checkPermissionsWithAccessMode(1000, 1000, perms, enclave.AccessMode_READ_ONLY))
	assert.True(t, checkPermissionsWithAccessMode(1000, 1000, perms, enclave.AccessMode_WRITE_ONLY))

	// Group member can read
	assert.True(t, checkPermissionsWithAccessMode(2000, 1000, perms, enclave.AccessMode_READ_ONLY))

	// Group member cannot write
	assert.False(t, checkPermissionsWithAccessMode(2000, 1000, perms, enclave.AccessMode_WRITE_ONLY))
}

func TestCheckPermissionsWithAccessMode_OthersRead(t *testing.T) {
	perms := &enclave.FilePerms{
		Uid:  1000,
		Gid:  1000,
		Mode: 0644, // Owner read/write, group/others read
	}

	// Others can read
	assert.True(t, checkPermissionsWithAccessMode(3000, 2000, perms, enclave.AccessMode_READ_ONLY))

	// Others cannot write
	assert.False(t, checkPermissionsWithAccessMode(3000, 2000, perms, enclave.AccessMode_WRITE_ONLY))

	// Others cannot read-write
	assert.False(t, checkPermissionsWithAccessMode(3000, 2000, perms, enclave.AccessMode_READ_WRITE))
}

func TestCheckPermissionsWithAccessMode_RootBypass(t *testing.T) {
	perms := &enclave.FilePerms{
		Uid:  1000,
		Gid:  1000,
		Mode: 0600, // Owner only
	}

	// Root (UID=0) can read and write any file
	assert.True(t, checkPermissionsWithAccessMode(0, 0, perms, enclave.AccessMode_READ_ONLY))
	assert.True(t, checkPermissionsWithAccessMode(0, 0, perms, enclave.AccessMode_WRITE_ONLY))
	assert.True(t, checkPermissionsWithAccessMode(0, 0, perms, enclave.AccessMode_READ_WRITE))
}

func TestCheckPermissionsWithAccessMode_NilPerms(t *testing.T) {
	// Nil permissions should deny access for safety
	assert.False(t, checkPermissionsWithAccessMode(1000, 1000, nil, enclave.AccessMode_READ_ONLY))
	assert.False(t, checkPermissionsWithAccessMode(1000, 1000, nil, enclave.AccessMode_WRITE_ONLY))
	assert.False(t, checkPermissionsWithAccessMode(0, 0, nil, enclave.AccessMode_READ_ONLY))
}

func TestCheckPermissionsWithAccessMode_AllModes(t *testing.T) {
	perms := &enclave.FilePerms{
		Uid:  1000,
		Gid:  1000,
		Mode: 0777, // All permissions
	}

	// Everyone should have all access modes
	for uid := int32(0); uid <= 3000; uid += 1000 {
		for gid := int32(0); gid <= 2000; gid += 1000 {
			assert.True(t, checkPermissionsWithAccessMode(uid, gid, perms, enclave.AccessMode_READ_ONLY))
			assert.True(t, checkPermissionsWithAccessMode(uid, gid, perms, enclave.AccessMode_WRITE_ONLY))
			assert.True(t, checkPermissionsWithAccessMode(uid, gid, perms, enclave.AccessMode_READ_WRITE))
		}
	}
}

// ===================== isHashInList Tests =====================

func TestIsHashInList_Found(t *testing.T) {
	hashes := []string{"hash1", "hash2", "hash3"}
	assert.True(t, isHashInList("hash1", hashes))
	assert.True(t, isHashInList("hash2", hashes))
	assert.True(t, isHashInList("hash3", hashes))
}

func TestIsHashInList_NotFound(t *testing.T) {
	hashes := []string{"hash1", "hash2", "hash3"}
	assert.False(t, isHashInList("hash4", hashes))
	assert.False(t, isHashInList("", hashes))
}

func TestIsHashInList_EmptyList(t *testing.T) {
	hashes := []string{}
	assert.False(t, isHashInList("hash1", hashes))
	assert.False(t, isHashInList("", hashes))
}

// ===================== parseCommandToParams Tests =====================

func TestParseCommandToParams_Normal(t *testing.T) {
	cmdLine := "psql -h localhost -U postgres -d mydb"
	cmd, params := parseCommandToParams(cmdLine)
	assert.Equal(t, "psql", cmd)
	assert.Equal(t, []string{"-h", "localhost", "-U", "postgres", "-d", "mydb"}, params)
}

func TestParseCommandToParams_Empty(t *testing.T) {
	cmd, params := parseCommandToParams("")
	assert.Equal(t, "", cmd)
	assert.Empty(t, params)
}

func TestParseCommandToParams_OnlyCommand(t *testing.T) {
	cmdLine := "ls"
	cmd, params := parseCommandToParams(cmdLine)
	assert.Equal(t, "ls", cmd)
	assert.Empty(t, params)
}

func TestParseCommandToParams_WithSpaces(t *testing.T) {
	cmdLine := "  psql   -h   localhost  "
	cmd, params := parseCommandToParams(cmdLine)
	assert.Equal(t, "psql", cmd)
	assert.Equal(t, []string{"-h", "localhost"}, params)
}

func TestParseCommandToParams_ComplexCommand(t *testing.T) {
	cmdLine := "docker run --name container -e PASSWORD=secret -v /data:/data image:latest"
	cmd, params := parseCommandToParams(cmdLine)
	assert.Equal(t, "docker", cmd)
	assert.Contains(t, params, "run")
	assert.Contains(t, params, "--name")
	assert.Contains(t, params, "container")
}

// ===================== AddPermitTicket Tests =====================

func TestAddPermitTicket_Success(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-123",
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
		CommandSpec:    "psql -h localhost",
	}

	resp, err := engine.AddPermitTicket(context.Background(), ticket)
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// Verify ticket was added
	storedTicket, exists := ledgerStore.GetTicket("test-uuid-123")
	assert.True(t, exists)
	assert.Equal(t, "test-uuid-123", storedTicket.GetUuid())
}

func TestAddPermitTicket_EmptyUUID(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	ticket := &enclave.PermitTicket{
		Uuid:           "", // Empty UUID
		TargetFilePath: "/etc/psql/passwd",
		Status:         "PENDING",
	}

	resp, err := engine.AddPermitTicket(context.Background(), ticket)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Message, "UUID cannot be empty")
}

func TestAddPermitTicket_EmptyTargetPath(t *testing.T) {
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := baseline.NewInMemoryBaselineStore()
	credAgentClient := &agent.CredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore(t.TempDir() + "/admin_password")
	require.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, []byte("test-key"), adminPasswordStore, nil)

	ticket := &enclave.PermitTicket{
		Uuid:           "test-uuid-456",
		TargetFilePath: "", // Empty target path
		Status:         "PENDING",
	}

	resp, err := engine.AddPermitTicket(context.Background(), ticket)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Message, "target file path cannot be empty")
}
