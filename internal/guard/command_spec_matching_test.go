package guard

import (
	"testing"

	"github.com/aliyun/credagent/internal/agent"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
)

func TestIsCommandSpecMatching(t *testing.T) {
	// Create a PolicyEngine instance for testing
	engine := &PolicyEngine{
		ledgerStore:     ledger.NewInMemoryLedger(),
		baselineStore:   baseline.NewInMemoryBaselineStore(),
		credAgentClient: &mockCredAgentClient{},
		masterKey:       make([]byte, 32), // dummy key for testing
	}

	tests := []struct {
		name     string
		expected string
		actual   string
		want     bool
	}{
		{
			name:     "exact match",
			expected: "aliyun ecs DescribeInstances",
			actual:   "aliyun ecs DescribeInstances",
			want:     true,
		},
		{
			name:     "same command with reordered args - user example",
			expected: "aliyun ecs --RegionId cn-hangzhou DescribeInstances",
			actual:   "aliyun ecs DescribeInstances --RegionId cn-hangzhou",
			want:     true,
		},
		{
			name:     "typo in actual command - should fail",
			expected: "aliyun ecs DescribeInstances",
			actual:   "aliyun ecs DescibeInstances", // intentional typo
			want:     false,
		},
		{
			name:     "actual has extra args beyond expected - should pass based on user requirement",
			expected: "aliyun ecs DescribeInstances",
			actual:   "aliyun ecs DescribeInstances --RegionId cn-hangzhou",
			want:     true,
		},
		{
			name:     "expected has args that actual doesn't have - should fail",
			expected: "aliyun ecs DescribeInstances --RegionId cn-hangzhou",
			actual:   "aliyun ecs DescribeInstances",
			want:     false,
		},
		{
			name:     "both have same args in different order",
			expected: "aliyun ecs --RegionId cn-hangzhou --InstanceType ecs.t5-lc1m1.small",
			actual:   "aliyun ecs --InstanceType ecs.t5-lc1m1.small --RegionId cn-hangzhou",
			want:     true,
		},
		{
			name:     "different commands",
			expected: "docker run nginx",
			actual:   "aliyun ecs DescribeInstances",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.isCommandSpecMatching(tt.expected, tt.actual)
			if got != tt.want {
				t.Errorf("isCommandSpecMatching() = %v, want %v", got, tt.want)
				t.Logf("Expected: '%s', Actual: '%s'", tt.expected, tt.actual)
			}
		})
	}
}

// Mock implementation of CredAgentClientInterface for testing
type mockCredAgentClient struct{}

func (m *mockCredAgentClient) AuditCommandWithTargetFile(command, intent, targetFile string) (*agent.AuditResponse, error) {
	return &agent.AuditResponse{Decision: "ALLOW"}, nil
}

func (m *mockCredAgentClient) InternalAuditLogic(intent, cmdline string) *agent.AuditResponse {
	return &agent.AuditResponse{Decision: "ALLOW"}
}

func (m *mockCredAgentClient) RequestPermissionViaEnclave(socketPath, intent, cmdline, targetFile string) (*agent.AuditResponse, error) {
	return &agent.AuditResponse{Decision: "ALLOW"}, nil
}
