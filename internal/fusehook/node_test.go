package fusehook

import (
	"context"
	"errors"
	"syscall"
	"testing"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/guard"
	"github.com/aliyun/credagent/internal/osutil"
	"google.golang.org/protobuf/types/known/emptypb"
)

// MockMonitorService is a mock implementation of guard.MonitorService for testing
type MockMonitorService struct {
	shouldAllowAccess      bool
	denialReason           string
	requestFUSEAccessFunc  func(ctx context.Context, objectPath string, process osutil.ProcessInf, req *guard.FUSEAccessRequest) (*enclave.AccessResponse, error)
	checkFileExistenceFunc func(ctx context.Context, procCtx *enclave.ProcessContext) (*enclave.FileExistenceResponse, error)
	listProtectedFilesFunc func(ctx context.Context, empty *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error)
}

func (m *MockMonitorService) RequestFUSEAccess(ctx context.Context, objectPath string, process osutil.ProcessInf, req *guard.FUSEAccessRequest) (*enclave.AccessResponse, error) {
	if m.requestFUSEAccessFunc != nil {
		return m.requestFUSEAccessFunc(ctx, objectPath, process, req)
	}

	return &enclave.AccessResponse{
		Status:        enclave.AccessStatus_ACCESS_GRANTED,
		PlaintextData: []byte("test data"),
		DenialReason:  m.denialReason,
	}, nil
}

func (m *MockMonitorService) CheckFileExistence(ctx context.Context, procCtx *enclave.ProcessContext) (*enclave.FileExistenceResponse, error) {
	if m.checkFileExistenceFunc != nil {
		return m.checkFileExistenceFunc(ctx, procCtx)
	}

	return &enclave.FileExistenceResponse{
		Exists:       m.shouldAllowAccess,
		IsProtected:  true,
		DenialReason: m.denialReason,
		Permissions:  nil,
	}, nil
}

func (m *MockMonitorService) ListProtectedFiles(ctx context.Context, empty *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error) {
	if m.listProtectedFilesFunc != nil {
		return m.listProtectedFilesFunc(ctx, empty)
	}

	return &enclave.ListProtectedFilesResponse{
		Baselines: []*enclave.CredentialBaseline{},
	}, nil
}

func TestNewShieldedNode(t *testing.T) {
	mock := &MockMonitorService{}
	store := baseline.NewInMemoryBaselineStore()
	node := NewShieldedNode(mock, store)

	if node == nil {
		t.Fatal("NewShieldedNode returned nil")
	}

	if node.monitor != mock {
		t.Error("monitor not set correctly")
	}

	if node.mountPoint != "/" {
		t.Errorf("Expected mountPoint to be '/', got %s", node.mountPoint)
	}
}

func TestShieldedNodeIsProtectedFile(t *testing.T) {
	tests := []struct {
		name           string
		mock           *MockMonitorService
		path           string
		expectedResult bool
	}{
		{
			name: "allowed access returns true",
			mock: &MockMonitorService{
				shouldAllowAccess: true,
			},
			path:           "/test/path",
			expectedResult: true,
		},
		{
			name: "denied access with 'No baseline found' returns false",
			mock: &MockMonitorService{
				shouldAllowAccess: false,
				denialReason:      "No baseline found",
			},
			path:           "/test/path",
			expectedResult: false,
		},
		{
			name: "denied access with 'no baseline' returns false",
			mock: &MockMonitorService{
				shouldAllowAccess: false,
				denialReason:      "baseline not found",
			},
			path:           "/test/path",
			expectedResult: false,
		},
		{
			name: "denied access with other reason returns true (baseline exists but access denied)",
			mock: &MockMonitorService{
				shouldAllowAccess: false,
				denialReason:      "Binary not allowed",
			},
			path:           "/test/path",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &ShieldedNode{
				monitor: tt.mock,
			}

			result := node.isProtectedFile(tt.path)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestShieldedNodeIsProtectedFileError(t *testing.T) {
	mock := &MockMonitorService{
		checkFileExistenceFunc: func(ctx context.Context, procCtx *enclave.ProcessContext) (*enclave.FileExistenceResponse, error) {
			return nil, errors.New("connection failed")
		},
	}

	node := &ShieldedNode{
		monitor: mock,
	}

	result := node.isProtectedFile("/test/path")
	if result != false {
		t.Errorf("Expected false when error occurs, got %v", result)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/", "/"},
		{"//", "/"},
		{"/path", "/path"},
		{"/path//to//file", "/path/to/file"},
		{"///multiple///slashes///", "/multiple/slashes/"},
		{"normal/path", "normal/path"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestShieldedNodeOpen(t *testing.T) {
	mock := &MockMonitorService{}
	node := &ShieldedNode{
		monitor: mock,
	}

	_, _, errno := node.Open(context.Background(), 0)

	if errno != syscall.EISDIR {
		t.Errorf("Expected EISDIR, got %v", errno)
	}
}

func TestShieldedNodeLookup(t *testing.T) {
	mock := &MockMonitorService{
		shouldAllowAccess: true,
	}

	node := &ShieldedNode{
		monitor:    mock,
		mountPoint: "/",
	}

	fullPath := node.mountPoint + "protected_file"

	isProtected := node.isProtectedFile(fullPath)
	if !isProtected {
		t.Errorf("Expected path to be protected")
	}

	child := &CredentialFileNode{
		name:       "protected_file",
		targetPath: fullPath,
		monitor:    mock,
	}

	if child.name != "protected_file" {
		t.Errorf("Expected name 'protected_file', got %s", child.name)
	}
	if child.targetPath != fullPath {
		t.Errorf("Expected targetPath %s, got %s", fullPath, child.targetPath)
	}
}

func TestShieldedNodeLookupNonProtected(t *testing.T) {
	mock := &MockMonitorService{
		shouldAllowAccess: false,
		denialReason:      "No baseline found",
	}

	node := &ShieldedNode{
		monitor:    mock,
		mountPoint: "/",
	}

	fullPath := node.mountPoint + "non_protected_file"

	isProtected := node.isProtectedFile(fullPath)
	if isProtected {
		t.Errorf("Expected path not to be protected")
	}
}
