package guard

import (
	"github.com/aliyun/credagent/internal/agent"
)

// MockCredAgentClient implements the CredAgentClientInterface for testing
type MockCredAgentClient struct {
	AuditResult *agent.AuditResponse
	Error       error
}

// NewMockCredAgentClient creates a new mock client with the specified behavior
func NewMockCredAgentClient(shouldAllow bool) *MockCredAgentClient {
	mock := &MockCredAgentClient{}
	if shouldAllow {
		mock.AuditResult = &agent.AuditResponse{
			Type:       "AUDIT_RESPONSE",
			Decision:   "ALLOW",
			Reason:     "Mock client allows access for testing",
			Confidence: 1.0,
		}
	} else {
		mock.AuditResult = &agent.AuditResponse{
			Type:       "AUDIT_RESPONSE",
			Decision:   "DENY",
			Reason:     "Mock client denies access for testing",
			Confidence: 0.8,
		}
	}
	return mock
}

// AuditCommandWithTargetFile mocks the audit functionality
func (m *MockCredAgentClient) AuditCommandWithTargetFile(command, intent, targetFile string) (*agent.AuditResponse, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if m.AuditResult != nil {
		return m.AuditResult, nil
	}
	// Default to allowing access for testing purposes
	return &agent.AuditResponse{
		Type:       "AUDIT_RESPONSE",
		Decision:   "ALLOW",
		Reason:     "Mock client allows access for testing",
		Confidence: 1.0,
	}, nil
}

// InternalAuditLogic provides fallback internal audit logic
func (m *MockCredAgentClient) InternalAuditLogic(intent, command string) *agent.AuditResponse {
	if m.AuditResult != nil {
		return m.AuditResult
	}
	// Default to allowing access for testing purposes
	return &agent.AuditResponse{
		Type:       "AUDIT_RESPONSE",
		Decision:   "ALLOW",
		Reason:     "Mock client allows access for testing",
		Confidence: 1.0,
	}
}

// RequestPermissionViaEnclave mocks the permission request functionality
func (m *MockCredAgentClient) RequestPermissionViaEnclave(socketPath, intent, cmdline, targetFile string) (*agent.AuditResponse, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if m.AuditResult != nil {
		return m.AuditResult, nil
	}
	// Default to allowing access for testing purposes
	return &agent.AuditResponse{
		Type:       "AUDIT_RESPONSE",
		Decision:   "ALLOW",
		Reason:     "Mock client allows access for testing",
		Confidence: 1.0,
	}, nil
}
