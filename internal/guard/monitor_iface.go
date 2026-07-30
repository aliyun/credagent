package guard

import (
	"context"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/osutil"
	"google.golang.org/protobuf/types/known/emptypb"
)

// FUSEAccessRequest carries the access-context info that the FUSE layer has
// beyond the process identity (which is carried by osutil.ProcessInf).
type FUSEAccessRequest struct {
	AccessMode       enclave.AccessMode
	Truncate         bool
	CurrentOpenCount int64
}

// MonitorService defines the internal interface for FUSE-layer access to the policy engine.
type MonitorService interface {
	RequestFUSEAccess(ctx context.Context, objectPath string, process osutil.ProcessInf, req *FUSEAccessRequest) (*enclave.AccessResponse, error)
	CheckFileExistence(ctx context.Context, req *enclave.ProcessContext) (*enclave.FileExistenceResponse, error)
	ListProtectedFiles(ctx context.Context, req *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error)
}
