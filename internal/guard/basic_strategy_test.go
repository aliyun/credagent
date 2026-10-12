package guard

import (
	"context"
	"os"
	"strings"
	"testing"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/agent"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// MockLedgerStore for testing
type MockLedgerStore struct {
	tickets map[string]*enclave.PermitTicket
}

func (m *MockLedgerStore) Save(ticket *enclave.PermitTicket) error {
	if m.tickets == nil {
		m.tickets = make(map[string]*enclave.PermitTicket)
	}
	m.tickets[ticket.Uuid] = ticket
	return nil
}

func (m *MockLedgerStore) Get(uuid string) (*enclave.PermitTicket, error) {
	if m.tickets == nil {
		return nil, nil
	}
	ticket, ok := m.tickets[uuid]
	if !ok {
		return nil, nil
	}
	return ticket, nil
}

func (m *MockLedgerStore) GetTicket(uuid string) (*enclave.PermitTicket, bool) {
	if m.tickets == nil {
		return nil, false
	}
	ticket, ok := m.tickets[uuid]
	return ticket, ok
}

func (m *MockLedgerStore) ConsumeTicket(uuid string, pid int32, strategy string) ledger.ConsumeResult {
	if m.tickets == nil {
		return ledger.ConsumeResult{
			Success:      false,
			DenialReason: "Ticket not found",
		}
	}
	ticket, ok := m.tickets[uuid]
	if !ok {
		return ledger.ConsumeResult{
			Success:      false,
			DenialReason: "Ticket not found",
		}
	}

	// For testing purposes, we'll just return success for BASIC strategy
	if strategy == "BASIC" {
		return ledger.ConsumeResult{
			Success: true,
		}
	}

	// Update ticket status to "BURNED" for ONE_TIME_USE strategy
	if strategy == "ONE_TIME_USE" {
		ticket.Status = "BURNED"
		m.tickets[uuid] = ticket
	}

	return ledger.ConsumeResult{
		Success: true,
	}
}

func (m *MockLedgerStore) ListActiveTickets() ([]*enclave.PermitTicket, error) {
	var tickets []*enclave.PermitTicket
	for _, ticket := range m.tickets {
		if ticket.Status == "ACTIVE" || ticket.Status == "PENDING" {
			tickets = append(tickets, ticket)
		}
	}
	return tickets, nil
}

func (m *MockLedgerStore) AddTicket(ticket *enclave.PermitTicket) error {
	return m.Save(ticket)
}

func (m *MockLedgerStore) CleanupExpired() {
	// For testing, just return
}

func (m *MockLedgerStore) ListTickets() []*enclave.PermitTicket {
	var tickets []*enclave.PermitTicket
	for _, ticket := range m.tickets {
		tickets = append(tickets, ticket)
	}
	return tickets
}

// MockBaselineStore for testing — wraps InMemoryBaselineStore so it satisfies baseline.BaselineStore.
type MockBaselineStore struct {
	*baseline.InMemoryBaselineStore
}

func newMockBaselineStore() *MockBaselineStore {
	return &MockBaselineStore{baseline.NewInMemoryBaselineStore()}
}

func TestBasicStrategy(t *testing.T) {
	// Setup
	mockLedger := &MockLedgerStore{}
	mockBaseline := newMockBaselineStore()
	mockAgent := &MockCredAgentClient{}
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_basic")
	assert.NoError(t, err)
	engine := NewPolicyEngine(mockLedger, mockBaseline, mockAgent, []byte("test-key"), adminPasswordStore, nil)

	// Create a test baseline with BASIC strategy
	testPath := "/test/credential"
	testData := []byte("test credential data")
	testBL := baseline.NewCredentialBaseline(
		"abcd1234efgh",
		baseline.FileMetadata{
			TargetPath:  testPath,
			Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0644},
		},
		&baseline.AccessRule{
			AllowedPrograms:      []string{"/usr/bin/test-binary"},
			VerificationStrategy: "BASIC",
		},
		testData,
	)

	err = mockBaseline.Save(testBL)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Create a test process that should pass the first layer validation
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary"),
		osutil.WithSha256("some-sha256-hash"),
		osutil.WithCmdline("/usr/bin/test-binary --arg value"),
	)

	// Test access request with BASIC strategy
	response, err := engine.RequestFUSEAccess(context.Background(), testPath, process, &FUSEAccessRequest{})
	if err != nil {
		t.Fatalf("RequestFUSEAccess returned error: %v", err)
	}

	// Verify that access was granted
	if response.Status != enclave.AccessStatus_ACCESS_GRANTED {
		t.Errorf("Expected access to be allowed, but got denial reason: %s", response.DenialReason)
	}

	// Verify FileSha is returned
	if response.FileSha == "" {
		t.Errorf("Expected FileSha to be returned")
	}

	// Read the content directly from the baseline store
	bl := mockBaseline.GetBySha(response.FileSha)
	if bl == nil {
		t.Fatalf("Expected baseline to exist for SHA %s", response.FileSha)
	}
	content, err := bl.FileContent()
	if err != nil {
		t.Fatalf("FileContent returned error: %v", err)
	}

	// Verify that the returned data matches what we stored
	if string(content) != string(testData) {
		t.Errorf("Expected returned data to match stored data. Got: %s, Expected: %s", string(content), string(testData))
	}

	logger.Info("BASIC strategy test passed: Access correctly granted without requiring UUID")
}

func TestBasicStrategyWithProvidedUUID(t *testing.T) {
	// Setup
	mockLedger := &MockLedgerStore{}
	mockBaseline := newMockBaselineStore()
	mockAgent := &MockCredAgentClient{} // Use the mock directly
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_basic_uuid")
	assert.NoError(t, err)
	engine := NewPolicyEngine(mockLedger, mockBaseline, mockAgent, []byte("test-key"), adminPasswordStore, nil)

	// Create a test baseline with BASIC strategy
	testPath := "/test/credential2"
	testData := []byte("test credential data 2")
	testBL2 := baseline.NewCredentialBaseline(
		"ijkl5678mnop",
		baseline.FileMetadata{
			TargetPath:  testPath,
			Permissions: &baseline.FilePerms{UID: 1000, GID: 1000, Mode: 0644},
		},
		&baseline.AccessRule{
			AllowedPrograms:      []string{"/usr/bin/test-binary2"},
			VerificationStrategy: "BASIC",
		},
		testData,
	)

	err = mockBaseline.Save(testBL2)
	if err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Create a test process with a UUID provided (should still pass with BASIC strategy)
	process := osutil.NewMockProcess(int32(os.Getpid()),
		osutil.WithUid(1000),
		osutil.WithGid(1000),
		osutil.WithExePath("/usr/bin/test-binary2"),
		osutil.WithSha256("some-other-sha256-hash"),
		osutil.WithCmdline("/usr/bin/test-binary2 --arg value"),
		osutil.WithPermitUuid("test-uuid-123"),
	)

	// Test access request with BASIC strategy and provided UUID
	response, err := engine.RequestFUSEAccess(context.Background(), testPath, process, &FUSEAccessRequest{})
	if err != nil {
		t.Fatalf("RequestFUSEAccess returned error: %v", err)
	}

	// Verify that access was granted despite the UUID being provided
	if response.Status != enclave.AccessStatus_ACCESS_GRANTED {
		t.Errorf("Expected access to be allowed (even with UUID provided), but got denial reason: %s", response.DenialReason)
	}

	// Verify FileSha is returned
	if response.FileSha == "" {
		t.Errorf("Expected FileSha to be returned")
	}

	// Read the content directly from the baseline store
	bl := mockBaseline.GetBySha(response.FileSha)
	if bl == nil {
		t.Fatalf("Expected baseline to exist for SHA %s", response.FileSha)
	}
	content, err := bl.FileContent()
	if err != nil {
		t.Fatalf("FileContent returned error: %v", err)
	}

	// Verify that the returned data matches what we stored
	if string(content) != string(testData) {
		t.Errorf("Expected returned data to match stored data. Got: %s, Expected: %s", string(content), string(testData))
	}

	logger.Info("BASIC strategy test with UUID passed: Access correctly granted even when UUID provided")
}

func TestRequestPermission(t *testing.T) {
	// Setup
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := newMockBaselineStore()
	mockCredAgentClient := &MockCredAgentClient{}
	masterKey := []byte("test-key-123456")
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_request_perm")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, mockCredAgentClient, masterKey, adminPasswordStore, nil)

	// Create request
	req := &enclave.RequestPermissionRequest{
		Intent:     "access file",
		Cmdline:    "ls -la /secure/file",
		TargetFile: "/secure/file",
	}

	// Execute
	resp, err := engine.RequestPermission(context.Background(), req)

	// Verify
	if err != nil {
		t.Fatalf("RequestPermission returned error: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success to be true, but got false")
	}

	if resp.Decision != "ALLOW" {
		t.Errorf("Expected decision to be ALLOW, but got %s", resp.Decision)
	}

	if resp.Uuid == "" {
		t.Errorf("Expected UUID to be generated, but got empty string")
	}

	if resp.Message == "" || !containsSubstring(resp.Message, "Access granted") {
		t.Errorf("Expected message to contain 'Access granted', but got: %s", resp.Message)
	}

	// Verify the ticket was added to the ledger
	ticket, exists := ledgerStore.GetTicket(resp.Uuid)
	if !exists {
		t.Errorf("Expected ticket to be added to ledger, but it wasn't found")
	} else {
		if ticket.TargetFilePath != "/secure/file" {
			t.Errorf("Expected ticket target file path to be '/secure/file', but got %s", ticket.TargetFilePath)
		}
		if ticket.Status != "ACTIVE" {
			t.Errorf("Expected ticket status to be 'ACTIVE', but got %s", ticket.Status)
		}
		if ticket.CommandSpec != "ls -la /secure/file" {
			t.Errorf("Expected ticket command spec to be 'ls -la /secure/file', but got %s", ticket.CommandSpec)
		}
	}
}

func TestRequestPermissionDeny(t *testing.T) {
	// Setup
	ledgerStore := ledger.NewInMemoryLedger()
	baselineStore := newMockBaselineStore()
	// Create a mock that returns DENY
	mockCredAgentClient := &MockCredAgentClientDeny{}
	masterKey := []byte("test-key-123456")
	adminPasswordStore, err := NewAdminPasswordStore("/tmp/test_admin_password_deny")
	assert.NoError(t, err)

	engine := NewPolicyEngine(ledgerStore, baselineStore, mockCredAgentClient, masterKey, adminPasswordStore, nil)

	// Create request
	req := &enclave.RequestPermissionRequest{
		Intent:     "delete file",
		Cmdline:    "rm -rf /secure/file",
		TargetFile: "/secure/file",
	}

	// Execute
	resp, err := engine.RequestPermission(context.Background(), req)

	// Verify
	if err != nil {
		t.Fatalf("RequestPermission returned error: %v", err)
	}

	if resp.Success {
		t.Errorf("Expected success to be false, but got true")
	}

	if resp.Decision != "DENY" {
		t.Errorf("Expected decision to be DENY, but got %s", resp.Decision)
	}

	if resp.Uuid != "" {
		t.Errorf("Expected UUID to be empty, but got %s", resp.Uuid)
	}

	if resp.Message == "" || !containsSubstring(resp.Message, "Access denied") {
		t.Errorf("Expected message to contain 'Access denied', but got: %s", resp.Message)
	}
}

// MockCredAgentClientDeny is a mock implementation that returns DENY
type MockCredAgentClientDeny struct{}

func (m *MockCredAgentClientDeny) AuditCommandWithTargetFile(command, intent, targetFile string) (*agent.AuditResponse, error) {
	return &agent.AuditResponse{Decision: "DENY", Reason: "Mock denied"}, nil
}

func (m *MockCredAgentClientDeny) InternalAuditLogic(intent, command string) *agent.AuditResponse {
	return &agent.AuditResponse{Decision: "DENY", Reason: "Mock internal denied"}
}

func (m *MockCredAgentClientDeny) RequestPermissionViaEnclave(socketPath, intent, cmdline, targetFile string) (*agent.AuditResponse, error) {
	return &agent.AuditResponse{Decision: "DENY", Reason: "Mock permission denied"}, nil
}

// Helper function to check if a string contains a substring
func containsSubstring(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 || strings.Contains(str, substr))
}
