package guard

import (
	"context"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"google.golang.org/protobuf/types/known/emptypb"
)

// EnclaveGuardServer implements the EnclaveGuardServiceServer interface
// This server handles requests from CredProtector and CredAgent that manage the baseline
type EnclaveGuardServer struct {
	enclave.UnimplementedEnclaveGuardServiceServer
	policyEngine *PolicyEngine
}

// NewEnclaveGuardServer creates a new instance of EnclaveGuardServer
func NewEnclaveGuardServer(engine *PolicyEngine) *EnclaveGuardServer {
	return &EnclaveGuardServer{
		policyEngine: engine,
	}
}

// OnboardFile handles file onboarding requests from CredProtector
func (s *EnclaveGuardServer) OnboardFile(ctx context.Context, req *enclave.OnboardFileRequest) (*enclave.StatusResponse, error) {
	return s.policyEngine.OnboardFile(ctx, req)
}

// ReleaseFile handles file release requests from CredProtector
func (s *EnclaveGuardServer) ReleaseFile(ctx context.Context, req *enclave.ReleaseFileRequest) (*enclave.ReleaseFileResponse, error) {
	return s.policyEngine.ReleaseFile(ctx, req)
}

// ListProtectedFiles lists all protected files in the baseline
func (s *EnclaveGuardServer) ListProtectedFiles(ctx context.Context, req *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error) {
	return s.policyEngine.ListProtectedFiles(ctx, req)
}

// AddPermitTicket adds a permit ticket to the ledger (used by CredAgent)
func (s *EnclaveGuardServer) AddPermitTicket(ctx context.Context, req *enclave.PermitTicket) (*enclave.StatusResponse, error) {
	return s.policyEngine.AddPermitTicket(ctx, req)
}

// RequestPermission handles requests for permission to access a credential file (for CredAgent)
func (s *EnclaveGuardServer) RequestPermission(ctx context.Context, req *enclave.RequestPermissionRequest) (*enclave.RequestPermissionResponse, error) {
	return s.policyEngine.RequestPermission(ctx, req)
}

// RemoveFile removes a credential file from the baseline by its hash value
func (s *EnclaveGuardServer) RemoveFile(ctx context.Context, req *enclave.RemoveFileRequest) (*enclave.StatusResponse, error) {
	return s.policyEngine.RemoveFile(ctx, req)
}
