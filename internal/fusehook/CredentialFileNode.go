package fusehook

import (
	"context"
	"fmt"
	"syscall"
	"time"

	enclave "github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/cache"
	"github.com/alibaba/CredAgent/internal/guard"
	"github.com/alibaba/CredAgent/pkg/crypto"
	"github.com/alibaba/CredAgent/pkg/logger"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func logMutationDenied(ctx context.Context, op, nodePath string) {
	if caller, ok := fuse.FromContext(ctx); ok {
		logger.Warn("FUSE: %s denied on read-only node %s (PID %d, UID %d)", op, nodePath, caller.Pid, caller.Uid)
	} else {
		logger.Warn("FUSE: %s denied on read-only node %s", op, nodePath)
	}
}

// CredentialFileNode represents the actual credential file in the FUSE filesystem
type CredentialFileNode struct {
	fs.Inode
	name          string
	targetPath    string
	monitor       guard.MonitorService
	baselineStore baseline.BaselineStore
	permissions   *enclave.FilePerms
	size          uint64
	creationTime  *uint64
}

var _ = (fs.NodeOpener)((*CredentialFileNode)(nil))
var _ = (fs.NodeGetattrer)((*CredentialFileNode)(nil))
var _ = (fs.NodeWriter)((*CredentialFileNode)(nil))
var _ = (fs.NodeSetattrer)((*CredentialFileNode)(nil))
var _ = (fs.NodeCreater)((*CredentialFileNode)(nil))
var _ = (fs.NodeLinker)((*CredentialFileNode)(nil))
var _ = (fs.NodeRenamer)((*CredentialFileNode)(nil))
var _ = (fs.NodeMkdirer)((*CredentialFileNode)(nil))

func (cf *CredentialFileNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	logMutationDenied(ctx, "Create", cf.targetPath)
	return nil, nil, 0, syscall.EACCES
}

func (cf *CredentialFileNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logMutationDenied(ctx, "Link", cf.targetPath)
	return nil, syscall.EACCES
}

func (cf *CredentialFileNode) Symlink(ctx context.Context, target string, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logMutationDenied(ctx, "Symlink", cf.targetPath)
	return nil, syscall.EACCES
}

func (cf *CredentialFileNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	logMutationDenied(ctx, "Rename", cf.targetPath)
	return syscall.EACCES
}

func (cf *CredentialFileNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	logMutationDenied(ctx, "Mkdir", cf.targetPath)
	return nil, syscall.EACCES
}

// Getattr returns the attributes of the credential file
func (cf *CredentialFileNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	logger.Debug("FUSE: Getattr called for file: %s", cf.targetPath)

	if cf.permissions != nil {
		out.Mode = uint32(cf.permissions.GetMode()) | syscall.S_IFREG
		out.Uid = uint32(cf.permissions.GetUid())
		out.Gid = uint32(cf.permissions.GetGid())
	} else {
		out.Mode = 0444 | syscall.S_IFREG
		out.Uid = 0
		out.Gid = 0
	}

	out.Size = cf.size

	if cf.creationTime != nil {
		ts := time.Unix(int64(*cf.creationTime), 0)
		out.Atime = uint64(ts.Unix())
		out.Mtime = uint64(ts.Unix())
		out.Ctime = uint64(ts.Unix())
		atime := ts
		mtime := ts
		ctime := ts
		out.SetTimes(&atime, &mtime, &ctime)
	}

	out.Nlink = 1

	logger.Debug("FUSE: Returning attributes for file %s - Mode: %d, Size: %d, Uid: %d, Gid: %d",
		cf.targetPath, out.Mode, out.Size, out.Uid, out.Gid)

	return 0
}

// Write implements the write operation for the credential file node.
// This method delegates to ShieldedFileHandle.Write when a valid file handle is provided.
// In go-fuse with FOPEN_DIRECT_IO, the kernel may call NodeWriter.Write instead of FileWriter.Write.
func (cf *CredentialFileNode) Write(ctx context.Context, fh fs.FileHandle, buf []byte, off int64) (uint32, syscall.Errno) {
	logger.Info("FUSE: Write request for %s with %d bytes at offset %d", cf.targetPath, len(buf), off)

	caller, ok := fuse.FromContext(ctx)
	if ok {
		logger.Info("FUSE: Write request from PID %d, UID %d to file %s", caller.Pid, caller.Uid, cf.targetPath)
	}

	if fh != nil {
		shieldedHandle, ok := fh.(*ShieldedFileHandle)
		if ok {
			logger.Debug("FUSE: Delegating Write to ShieldedFileHandle for SHA: %s", shieldedHandle.sha)
			return shieldedHandle.Write(ctx, buf, off)
		}
		logger.Warn("FUSE: File handle is not ShieldedFileHandle type")
	}

	logger.Warn("FUSE: Write attempted without valid file handle on credential file: %s", cf.targetPath)
	return 0, syscall.EACCES
}

// Setattr implements attribute setting for the credential file node.
func (cf *CredentialFileNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) (errno syscall.Errno) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("FUSE: Setattr panic for %s: %v", cf.targetPath, r)
			errno = syscall.EACCES
		}
	}()

	caller, ok := fuse.FromContext(ctx)
	if ok {
		logger.Info("FUSE: Setattr request from PID %d, UID %d to file %s", caller.Pid, caller.Uid, cf.targetPath)
	}

	if in.Valid&fuse.FATTR_SIZE != 0 {
		newSize := in.Size
		logger.Debug("FUSE: Setattr requesting size change (truncate) to %d bytes for file %s", newSize, cf.targetPath)

		if f != nil {
			shieldedHandle, ok := f.(*ShieldedFileHandle)
			if ok && shieldedHandle.writeMode {
				if err := cf.truncateBaseline(shieldedHandle.sha, int64(newSize)); err != nil {
					logger.Error("FUSE: Truncate failed for SHA %s: %v", shieldedHandle.sha, err)
					return syscall.EIO
				}
				cf.size = newSize
				logger.Debug("FUSE: Successfully truncated SHA %s to %d bytes", shieldedHandle.sha, newSize)
			} else {
				logger.Warn("FUSE: Cannot truncate - handle not opened for writing or not ShieldedFileHandle")
				return syscall.EACCES
			}
		} else {
			logger.Debug("FUSE: Truncate without open detected for file %s", cf.targetPath)

			ps := cache.GetOrCreate(caller.Pid)
			resp, err := cf.monitor.RequestFUSEAccess(ctx, cf.targetPath, ps, &guard.FUSEAccessRequest{
				AccessMode: enclave.AccessMode_WRITE_ONLY,
				Truncate:   newSize == 0,
			})
			if err != nil {
				logger.Error("FUSE: RequestFUSEAccess error for truncate: %v", err)
				return syscall.EACCES
			}

			if resp.GetStatus() != enclave.AccessStatus_ACCESS_GRANTED {
				return syscall.EACCES
			}

			fileSha := resp.GetFileSha()
			if err := cf.truncateBaseline(fileSha, int64(newSize)); err != nil {
				logger.Error("FUSE: Truncate failed for SHA %s: %v", fileSha, err)
				return syscall.EIO
			}

			cf.size = newSize
			logger.Info("FUSE: Successfully completed truncate without open for file %s, new size: %d", cf.targetPath, newSize)
		}
	}

	return 0
}

// truncateBaseline truncates a baseline's content to the given size and persists the change.
func (cf *CredentialFileNode) truncateBaseline(sha string, newSize int64) error {
	bl := cf.baselineStore.GetBySha(sha)
	if bl == nil {
		return fmt.Errorf("baseline not found for SHA: %s", sha)
	}

	currentContent, err := bl.FileContent()
	if err != nil {
		return fmt.Errorf("failed to load file content: %w", err)
	}

	var newContent []byte
	if newSize == 0 {
		newContent = nil
	} else if int(newSize) < len(currentContent) {
		newContent = make([]byte, newSize)
		copy(newContent, currentContent[:newSize])
	} else {
		newContent = make([]byte, newSize)
		copy(newContent, currentContent)
	}

	bl.SetFileContent(newContent)
	crypto.ZeroBytes(currentContent)
	meta := bl.Metadata()
	meta.Size = newSize
	bl.SetMetadata(meta)

	return cf.baselineStore.Set(bl.Metadata().TargetPath, bl)
}

// Open intercepts the file open request for the credential file.
func (cf *CredentialFileNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("FUSE: Open panic for %s: %v", cf.targetPath, r)
			fh, fuseFlags, errno = nil, 0, syscall.EACCES
		}
	}()

	caller, ok := fuse.FromContext(ctx)
	if !ok {
		logger.Error("FUSE: Failed to extract caller context from FUSE context")
		return nil, 0, syscall.EACCES
	}

	ps := cache.GetOrCreate(caller.Pid)

	if ps.IsUntrusted() {
		logger.Warn("[denied] Object: %s, Program(%d): %s, Reason: untrusted (cross-process fd share violation)",
			cf.targetPath, caller.Pid, ps.GetBriefCmdline())
		return nil, 0, syscall.EACCES
	}

	isWriteOnly := flags&syscall.O_WRONLY != 0
	isReadWrite := flags&syscall.O_RDWR != 0
	isTruncate := flags&syscall.O_TRUNC != 0

	var accessMode enclave.AccessMode
	if isReadWrite {
		accessMode = enclave.AccessMode_READ_WRITE
	} else if isWriteOnly {
		accessMode = enclave.AccessMode_WRITE_ONLY
	} else {
		accessMode = enclave.AccessMode_READ_ONLY
	}

	logger.Debug("FUSE: PID %d, UID %d Open %s (mode=%s, trunc=%v)", caller.Pid, caller.Uid, cf.targetPath, accessMode.String(), isTruncate)

	currentOpenCount := ps.GetOpenCount(cf.targetPath)

	resp, err := cf.monitor.RequestFUSEAccess(ctx, cf.targetPath, ps, &guard.FUSEAccessRequest{
		AccessMode:       accessMode,
		Truncate:         isTruncate,
		CurrentOpenCount: currentOpenCount,
	})
	if err != nil {
		logger.Error("FUSE: RequestFUSEAccess error: %v", err)
		return nil, 0, syscall.EACCES
	}

	logger.Debug("FUSE: RequestFUSEAccess response - Status: %d, Reason: %s", resp.GetStatus(), resp.GetDenialReason())

	if resp.GetStatus() == enclave.AccessStatus_ACCESS_BASELINE_DENIED {
		return nil, 0, syscall.EACCES
	}

	if resp.GetStatus() == enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET {
		return nil, 0, syscall.ENOTSUP
	}

	if resp.GetStatus() == enclave.AccessStatus_ACCESS_PERMIT_DENIED {
		return nil, 0, syscall.EACCES
	}

	if resp.GetStatus() != enclave.AccessStatus_ACCESS_GRANTED {
		return nil, 0, syscall.EACCES
	}

	fileSha := resp.GetFileSha()

	ps.IncrementOpenCount(cf.targetPath)

	writeMode := isWriteOnly || isReadWrite

	if isTruncate && writeMode {
		bl := cf.baselineStore.GetBySha(fileSha)
		if bl != nil {
			bl.SetFileContent(nil)
			meta := bl.Metadata()
			meta.Size = 0
			bl.SetMetadata(meta)
			if err := cf.baselineStore.Set(bl.Metadata().TargetPath, bl); err != nil {
				briefCmd := ps.GetBriefCmdline()
				logger.Warn("[denied] Object: %s, Program(%d): %s, Reason: truncate baseline failed: %v",
					cf.targetPath, caller.Pid, briefCmd, err)
				return nil, 0, syscall.EIO
			}
			cf.size = 0
		}
	}

	ps.IncrementActiveHandle(cf.targetPath)
	ps.MarkActive()

	briefCmd := ps.GetBriefCmdline()
	if ps.IsHarnessed() {
		logger.Info("[allowed] Object: %s, harnessed Program(%d): %s", cf.targetPath, caller.Pid, briefCmd)
	} else {
		logger.Info("[allowed] Object: %s, Program(%d): %s", cf.targetPath, caller.Pid, briefCmd)
	}

	return &ShieldedFileHandle{
		sha:       fileSha,
		node:      cf,
		pid:       caller.Pid,
		store:     cf.baselineStore,
		writeMode: writeMode,
		process:   ps,
	}, fuse.FOPEN_DIRECT_IO, 0
}

// ShieldedFileHandle holds the baseline reference for a specific file descriptor.
type ShieldedFileHandle struct {
	sha       string
	node      *CredentialFileNode
	pid       uint32
	store     baseline.BaselineStore
	writeMode bool
	process   cache.ProcessInf
}

var _ = (fs.FileReader)((*ShieldedFileHandle)(nil))
var _ = (fs.FileReleaser)((*ShieldedFileHandle)(nil))
var _ = (fs.FileWriter)((*ShieldedFileHandle)(nil))
var _ = (fs.FileFlusher)((*ShieldedFileHandle)(nil))
var _ = (fs.FileFsyncer)((*ShieldedFileHandle)(nil))

// Read serves the bytes by fetching content directly from the baseline store.
func (fh *ShieldedFileHandle) Read(ctx context.Context, dest []byte, off int64) (result fuse.ReadResult, errno syscall.Errno) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("FUSE: Read panic for %s: %v", fh.node.targetPath, r)
			result, errno = nil, syscall.EACCES
		}
	}()
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		logger.Error("FUSE: Read denied on %s — cannot determine caller identity", fh.node.targetPath)
		return nil, syscall.EACCES
	}
	if caller.Pid != fh.pid && cache.FdShareCheckEnabled() {
		readerPs := cache.GetOrCreate(caller.Pid)
		reason := fmt.Sprintf("cross-process fd share detected (opener PID %d)", fh.pid)
		readerPs.MarkUntrusted(reason)
		fh.process.MarkUntrusted(reason)
		logger.Warn("[denied] Object: %s, Program(%d): %s, Reason: [fd_share_check] cross-process fd share detected (opener PID %d), both PIDs marked untrusted",
			fh.node.targetPath, caller.Pid, readerPs.GetBriefCmdline(), fh.pid)
		return nil, syscall.EACCES
	}

	logger.Debug("FUSE: Reading from ShieldedFileHandle, SHA: %s, offset: %d, length: %d", fh.sha, off, len(dest))

	bl := fh.store.GetBySha(fh.sha)
	if bl == nil {
		logger.Error("FUSE: Baseline not found for SHA: %s", fh.sha)
		return nil, syscall.EIO
	}

	content, err := bl.FileContent()
	if err != nil {
		logger.Error("FUSE: Failed to load file content for SHA %s: %v", fh.sha, err)
		return nil, syscall.EIO
	}

	if int(off) >= len(content) {
		logger.Debug("FUSE: Reached EOF, offset %d exceeds content length %d", off, len(content))
		return fuse.ReadResultData([]byte{}), 0
	}

	end := int(off) + len(dest)
	if end > len(content) {
		end = len(content)
	}

	logger.Debug("FUSE: Returning %d bytes from offset %d to %d", end-int(off), off, end)
	return fuse.ReadResultData(content[off:end]), 0
}

// Write writes data to the file handle at the specified offset
func (fh *ShieldedFileHandle) Write(ctx context.Context, data []byte, off int64) (written uint32, errno syscall.Errno) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("FUSE: Write panic for %s: %v", fh.node.targetPath, r)
			written, errno = 0, syscall.EACCES
		}
	}()
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		logger.Error("FUSE: Write denied on %s — cannot determine caller identity", fh.node.targetPath)
		return 0, syscall.EACCES
	}
	if caller.Pid != fh.pid && cache.FdShareCheckEnabled() {
		writerPs := cache.GetOrCreate(caller.Pid)
		reason := fmt.Sprintf("cross-process fd share detected (opener PID %d)", fh.pid)
		writerPs.MarkUntrusted(reason)
		fh.process.MarkUntrusted(reason)
		logger.Warn("[denied] Object: %s, Program(%d): %s, Reason: [fd_share_check] cross-process fd share detected (opener PID %d), both PIDs marked untrusted",
			fh.node.targetPath, caller.Pid, writerPs.GetBriefCmdline(), fh.pid)
		return 0, syscall.EACCES
	}

	if !fh.writeMode {
		logger.Warn("FUSE: Write attempted on read-only handle for SHA %s", fh.sha)
		return 0, syscall.EACCES
	}

	logger.Debug("FUSE: Writing to ShieldedFileHandle, SHA: %s, offset: %d, length: %d", fh.sha, off, len(data))

	bl := fh.store.GetBySha(fh.sha)
	if bl == nil {
		logger.Error("FUSE: Baseline not found for SHA: %s", fh.sha)
		return 0, syscall.EIO
	}

	currentContent, err := bl.FileContent()
	if err != nil {
		logger.Error("FUSE: Failed to load file content for SHA %s: %v", fh.sha, err)
		return 0, syscall.EIO
	}

	newSize := off + int64(len(data))
	if newSize < int64(len(currentContent)) {
		newSize = int64(len(currentContent))
	}

	newContent := make([]byte, newSize)
	if len(currentContent) > 0 {
		copy(newContent, currentContent)
	}
	copy(newContent[off:], data)

	bl.SetFileContent(newContent)
	crypto.ZeroBytes(currentContent)
	meta := bl.Metadata()
	meta.Size = int64(len(newContent))
	bl.SetMetadata(meta)

	if err := fh.store.Set(bl.Metadata().TargetPath, bl); err != nil {
		logger.Error("FUSE: Failed to write to baseline for SHA %s: %v", fh.sha, err)
		return 0, syscall.EIO
	}

	fh.node.size = uint64(len(newContent))
	logger.Debug("FUSE: Successfully wrote %d bytes to SHA %s at offset %d, new size: %d",
		len(data), fh.sha, off, len(newContent))
	return uint32(len(data)), 0
}

func (fh *ShieldedFileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return syscall.EACCES
	}
	if caller.Pid != fh.pid && cache.FdShareCheckEnabled() {
		syncerPs := cache.GetOrCreate(caller.Pid)
		reason := fmt.Sprintf("cross-process fd share detected (opener PID %d)", fh.pid)
		syncerPs.MarkUntrusted(reason)
		fh.process.MarkUntrusted(reason)
		logger.Warn("[denied] Object: %s, Program(%d): %s, Reason: [fd_share_check] cross-process fd share detected (opener PID %d), both PIDs marked untrusted",
			fh.node.targetPath, caller.Pid, syncerPs.GetBriefCmdline(), fh.pid)
		return syscall.EACCES
	}
	return 0
}

// Flush is a no-op — writes persist immediately to the baseline store.
func (fh *ShieldedFileHandle) Flush(ctx context.Context) syscall.Errno {
	logger.Debug("FUSE: Flush for SHA %s (no-op, writes persist immediately)", fh.sha)
	return 0
}

// Release is called when the file handle is closed
func (fh *ShieldedFileHandle) Release(ctx context.Context) syscall.Errno {
	if fh.process != nil {
		fh.process.DecrementActiveHandle(fh.node.targetPath)
	}
	logger.Debug("FUSE: Released file handle for PID %d on file %s (SHA %s)", fh.pid, fh.node.targetPath, fh.sha)
	return 0
}
