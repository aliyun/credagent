package fusehook

import (
	"context"
	"hash/fnv"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	enclave "github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/guard"
	"github.com/aliyun/credagent/pkg/logger"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ShieldedNode represents the root of the FUSE filesystem that can handle multiple protected files.
type ShieldedNode struct {
	fs.Inode
	mountPoint    string // Mount point for the FUSE filesystem
	monitor       guard.MonitorService
	baselineStore baseline.BaselineStore
	mu            sync.RWMutex // Protects access to dynamic file tracking
}

var _ = (fs.NodeLookuper)((*ShieldedNode)(nil))
var _ = (fs.NodeOpener)((*ShieldedNode)(nil))
var _ = (fs.NodeWriter)((*ShieldedNode)(nil))
var _ = (fs.NodeSetattrer)((*ShieldedNode)(nil))
var _ = (fs.NodeCreater)((*ShieldedNode)(nil))
var _ = (fs.NodeLinker)((*ShieldedNode)(nil))
var _ = (fs.NodeRenamer)((*ShieldedNode)(nil))
var _ = (fs.NodeReaddirer)((*ShieldedNode)(nil))

// NewShieldedNode creates a new FUSE node that can handle multiple protected files
func NewShieldedNode(monitor guard.MonitorService, store baseline.BaselineStore) *ShieldedNode {
	return &ShieldedNode{
		monitor:       monitor,
		baselineStore: store,
		mountPoint:    "/",
	}
}

// Lookup handles path resolution for the FUSE filesystem.
// This is called when the kernel wants to resolve a path component.
// With the new design, we only serve files by their SHA256 values in the root directory
func (n *ShieldedNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logger.Debug("FUSE: Lookup called for name: %s", name)

	// For the new design, we'll query the enclave to see if the SHA256 exists in baseline
	procCtx := &enclave.ProcessContext{
		ObjectPath: name, // For the new design, we expect the name to be the SHA256
	}

	// Use CheckFileExistence instead of RequestFUSEAccess to just check existence
	// This single call should return all metadata needed for the file
	existenceResp, err := n.monitor.CheckFileExistence(context.Background(), procCtx)
	if err != nil {
		logger.Warn("FUSE: SHA256 %s doesn't exists in baseline: %v", name, err)
		// According to the new design, we should NOT create virtual directories
		// If the SHA256 doesn't exist in baseline, return ENOENT
		return nil, syscall.ENOENT // No such file
	}

	// Check if file exists in baseline
	if existenceResp.GetExists() {
		logger.Debug("FUSE: Found protected file with SHA256: %s", name)
		// This is a protected credential file with the name being its SHA256

		// Use permissions from the existence response if available
		perms := existenceResp.GetPermissions()
		if perms != nil {
			// Apply security restrictions:
			// 1. Owner always has read permission (r--)
			// 2. Group permissions come from original file (--- or -w- or --x or -wx, etc.)
			// 3. Others have read permissions (--r) as requested
			// 4. No one has write or execute permissions beyond original restrictions

			originalMode := uint32(perms.GetMode())

			// Start with owner read permission guaranteed (0400)
			newMode := uint32(syscall.S_IRUSR)

			// Preserve original group read permission if it existed (0040)
			if (originalMode & syscall.S_IRGRP) != 0 {
				newMode |= syscall.S_IRGRP
			}

			// Add read permission for others (0004) as requested
			newMode |= syscall.S_IROTH

			// Remove all execute permissions (owner, group, others) - no one gets 'x'
			// Remove all write permissions (owner, group, others) - no one gets 'w'
			// Only preserve read permissions as determined above

			out.Attr.Mode = newMode | syscall.S_IFREG
			out.Attr.Uid = uint32(perms.GetUid())
			out.Attr.Gid = uint32(perms.GetGid())
		} else {
			// Fallback to default permissions if not available
			out.Attr.Mode = 0444 | syscall.S_IFREG // Readable by owner - important for access
			out.Attr.Uid = 0                       // Default to root
			out.Attr.Gid = 0                       // Default to root group
		}

		// Set the size from the existence response
		out.Attr.Size = uint64(existenceResp.GetSize())

		// Set the creation time from the existence response if available
		var creationTime *uint64
		if existenceResp.GetCreationTime() != nil {
			// Convert protobuf timestamp to uint64 seconds since epoch
			ctimeSecs := uint64(existenceResp.GetCreationTime().GetSeconds())
			creationTime = &ctimeSecs
		}

		// Generate a unique inode number based on the SHA256 name to avoid collisions
		inodeNumber := generateInodeNumber(name)
		out.Attr.Ino = inodeNumber // Set inode explicitly

		child := &CredentialFileNode{
			name:          name,
			targetPath:    name,
			monitor:       n.monitor,
			baselineStore: n.baselineStore,
			permissions:   perms,
			size:          uint64(existenceResp.GetSize()),
			creationTime:  creationTime,
		}

		return n.NewInode(ctx, child, fs.StableAttr{
			Mode: out.Attr.Mode,
			Ino:  inodeNumber, // Use unique inode number for the credential file
		}), 0
	} else {
		// Return ENOENT for any file that doesn't exist in baseline
		logger.Warn("FUSE: SHA256 %s not found in baseline", name)
		return nil, syscall.ENOENT
	}
}

// isProtectedFile checks if the given path corresponds to a protected file
// by querying the EnclaveDaemon to see if there's a baseline rule for this path
func (n *ShieldedNode) isProtectedFile(path string) bool {
	logger.Debug("FUSE: Checking if path is protected: %s", path)

	// First, try the path as-is
	procCtx := &enclave.ProcessContext{
		ObjectPath: path,
		// Other fields can be empty for this check
	}

	logger.Debug("FUSE: Checking file existence to see if %s is protected", path)

	// Use CheckFileExistence instead of RequestFUSEAccess for efficiency
	existenceResp, err := n.monitor.CheckFileExistence(context.Background(), procCtx)
	if err != nil {
		logger.Error("FUSE: Error checking if %s is protected: %v", path, err)
		return false
	}

	logger.Debug("FUSE: Got response for path %s - Exists: %t, IsProtected: %t, Reason: %s",
		path, existenceResp.GetExists(), existenceResp.GetIsProtected(), existenceResp.GetDenialReason())

	// Check if the file exists in baseline
	if existenceResp.GetExists() {
		// If file exists in baseline, it's protected
		logger.Debug("FUSE: File %s exists in baseline, it's a protected file", path)
		return true
	} else if strings.Contains(existenceResp.GetDenialReason(), "No baseline found") ||
		strings.Contains(existenceResp.GetDenialReason(), "no baseline") ||
		strings.Contains(existenceResp.GetDenialReason(), "baseline not found") {
		// If the denial reason indicates no baseline exists, it's not protected
		// Try checking if it's a relative path by extracting the filename
		basePath := filepath.Base(path)
		logger.Debug("FUSE: No baseline found for %s, trying basename: %s", path, basePath)

		// Try checking if just the basename exists in baseline
		// For example, if full path is /home/user/test_credential1.txt
		// but the baseline stores it as ./test_credential1.txt
		relProcCtx := &enclave.ProcessContext{
			ObjectPath: "./" + basePath,
		}

		logger.Debug("FUSE: Checking file existence for alternative path: %s", relProcCtx.ObjectPath)

		relResp, relErr := n.monitor.CheckFileExistence(context.Background(), relProcCtx)
		if relErr != nil {
			logger.Error("FUSE: Error checking alternative path %s: %v", relProcCtx.ObjectPath, relErr)
			return false
		}

		logger.Debug("FUSE: Got response for alternative path %s - Exists: %t, IsProtected: %t, Reason: %s",
			relProcCtx.ObjectPath, relResp.GetExists(), relResp.GetIsProtected(), relResp.GetDenialReason())

		if relResp.GetExists() {
			logger.Debug("FUSE: Alternative path %s is protected", relProcCtx.ObjectPath)
			return true
		} else if !strings.Contains(relResp.GetDenialReason(), "No baseline found") &&
			!strings.Contains(relResp.GetDenialReason(), "no baseline") &&
			!strings.Contains(relResp.GetDenialReason(), "baseline not found") {
			// If there's a different denial reason (like binary not allowed),
			// it means the baseline exists but access was denied for other reasons
			logger.Debug("FUSE: Baseline exists for %s but access denied for other reasons", relProcCtx.ObjectPath)
			return true
		}

		logger.Debug("FUSE: Path %s is not protected", path)
		return false
	} else {
		// For other denial reasons (binary not allowed, etc.), it means a baseline exists
		// but access was denied for other reasons, so the file is protected
		logger.Debug("FUSE: Baseline exists for %s but access denied for other reasons (%s)", path, existenceResp.GetDenialReason())
		return true
	}
}

func (n *ShieldedNode) Write(ctx context.Context, fh fs.FileHandle, buf []byte, off int64) (uint32, syscall.Errno) {
	logMutationDenied(ctx, "Write", n.mountPoint)
	return 0, syscall.EACCES
}

func (n *ShieldedNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	logMutationDenied(ctx, "Setattr", n.mountPoint)
	return syscall.EACCES
}

func (n *ShieldedNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	logMutationDenied(ctx, "Create", n.mountPoint)
	return nil, nil, 0, syscall.EACCES
}

func (n *ShieldedNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logMutationDenied(ctx, "Link", n.mountPoint)
	return nil, syscall.EACCES
}

func (n *ShieldedNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	logMutationDenied(ctx, "Rename", n.mountPoint)
	return syscall.EACCES
}

func (n *ShieldedNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logMutationDenied(ctx, "Mkdir", n.mountPoint)
	return nil, syscall.EACCES
}

// Open intercepts the file open request for the root node.
func (n *ShieldedNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// This should only be called if someone tries to open the root itself
	// For our use case, we want to handle opens at the specific file level
	return nil, 0, syscall.EISDIR
}

// isHex checks if a string contains only hexadecimal characters
func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// normalizePath removes double slashes and ensures proper formatting
func normalizePath(path string) string {
	// Replace multiple slashes with single slash
	result := ""
	prevCharIsSlash := false

	for _, char := range path {
		if char == '/' {
			if !prevCharIsSlash {
				result += string(char)
				prevCharIsSlash = true
			}
		} else {
			result += string(char)
			prevCharIsSlash = false
		}
	}

	return result
}

// generateInodeNumber generates a unique inode number based on the SHA256 name
func generateInodeNumber(name string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	ino := h.Sum64()

	// Inodes 0 and 1 are reserved. If we get one, just pick another nearby number.
	// This is a simple strategy that is sufficient given the rarity of collisions.
	if ino <= 1 {
		ino += 2 // eg., if ino is 0 or 1, it becomes 2 or 3.
	}
	return ino
}

// Readdir lists all protected files (by their SHA256 names) in the root directory
func (n *ShieldedNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	logger.Debug("FUSE: Readdir called on shield node")

	// Query the enclave to get all protected files in the baseline
	// Use empty message as the parameter according to the protobuf definition
	listResp, err := n.monitor.ListProtectedFiles(context.Background(), &emptypb.Empty{})
	if err != nil {
		logger.Error("FUSE: Failed to list protected files from enclave: %v", err)
		// If we can't get the list from the enclave, return empty directory
		return nil, syscall.EIO // Input/Output Error
	}

	// Create entries for each protected file
	var entries []fuse.DirEntry
	for _, baseline := range listResp.GetBaselines() {
		// Use the SHA as the filename in the FUSE directory
		sha := baseline.GetSha()
		if sha != "" {
			// BEST PRACTICE: Readdir should only provide the name and type.
			// The kernel will call Lookup for each entry to get detailed attributes (like Ino, full mode, etc.).
			entry := fuse.DirEntry{
				Name: sha,
				Mode: syscall.S_IFREG, // Regular file
			}
			entries = append(entries, entry)
		}
	}

	logger.Debug("FUSE: Returning %d entries from Readdir", len(entries))
	return fs.NewListDirStream(entries), 0
}
