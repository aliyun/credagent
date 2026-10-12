package guard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/agent"
	"github.com/aliyun/credagent/internal/baseline"
	"github.com/aliyun/credagent/internal/ledger"
	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PolicyEngine is the CredGuard policy enforcement point.
type PolicyEngine struct {
	ledgerStore         ledger.LedgerStore
	baselineStore       baseline.BaselineStore
	credAgentClient     agent.CredAgentClientInterface
	masterKey           []byte
	adminPasswordStore  *AdminPasswordStore
	riskCheckConfig     *osutil.RiskCheckConfig
	enclave.UnimplementedEnclaveGuardServiceServer
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine(ledgerStore ledger.LedgerStore, baselineStore baseline.BaselineStore, credAgentClient agent.CredAgentClientInterface, masterKey []byte, adminPasswordStore *AdminPasswordStore, riskCheckConfig *osutil.RiskCheckConfig) *PolicyEngine {
	return &PolicyEngine{
		ledgerStore:        ledgerStore,
		baselineStore:      baselineStore,
		credAgentClient:    credAgentClient,
		masterKey:          masterKey,
		adminPasswordStore: adminPasswordStore,
		riskCheckConfig:    riskCheckConfig,
	}
}

// ─── Helper: convert internal baseline → proto (for gRPC responses) ───────────

// toProtoBaseline maps a *baseline.CredentialBaseline to an *enclave.CredentialBaseline
// for use in gRPC responses.  File content is NEVER included for security.
func toProtoBaseline(bl *baseline.CredentialBaseline) *enclave.CredentialBaseline {
	if bl == nil {
		return nil
	}
	meta := bl.Metadata()
	pb := &enclave.CredentialBaseline{
		TargetPath: meta.TargetPath,
		Ctime:      meta.Ctime,
		Size:       meta.Size,
		Sha:        bl.SHA(),
	}
	if meta.Permissions != nil {
		pb.Permissions = &enclave.FilePerms{
			Uid:  meta.Permissions.UID,
			Gid:  meta.Permissions.GID,
			Mode: meta.Permissions.Mode,
		}
	}
	rule, err := bl.Rule()
	if err != nil {
		logger.Warn("toProtoBaseline: failed to load rule for sha=%s: %v", bl.SHA(), err)
		return pb
	}
	if rule != nil {
		pb.VerificationStrategy = rule.VerificationStrategy
		pb.AllowedBinaries = rule.AllowedPrograms
		pb.AllowedBinariesSha256 = rule.AllowedProgramsSha256
		pb.MaxOpenCount = rule.MaxOpenCount
		pb.Writable = rule.Writable
		pb.Measure = rule.Measure
	}
	return pb
}

// ─── EnclaveGuardService ──────────────────────────────────────────────────────

// OnboardFile stores a credential file in the enclave with optional encryption.
func (p *PolicyEngine) OnboardFile(ctx context.Context, req *enclave.OnboardFileRequest) (*enclave.StatusResponse, error) {
	targetPath := req.GetTargetPath()
	if targetPath == "" || len(req.GetPlaintextData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "target_path and plaintext_data must not be empty")
	}

	pathHash := sha256.Sum256([]byte(targetPath))
	baseShaIdentifier := hex.EncodeToString(pathHash[:])[:12]
	shaIdentifier := p.generateUniqueSha(baseShaIdentifier)

	var perms *baseline.FilePerms
	if req.GetPermissions() != nil {
		perms = &baseline.FilePerms{
			UID:  req.GetPermissions().GetUid(),
			GID:  req.GetPermissions().GetGid(),
			Mode: req.GetPermissions().GetMode(),
		}
	}

	bl := baseline.NewCredentialBaseline(
		shaIdentifier,
		baseline.FileMetadata{
			TargetPath:  targetPath,
			Permissions: perms,
			Ctime:       timestamppb.Now(),
			Size:        int64(len(req.GetPlaintextData())),
		},
		&baseline.AccessRule{
			VerificationStrategy:  req.GetVerificationStrategy(),
			AllowedPrograms:       req.GetAllowedBinaries(),
			AllowedProgramsSha256: req.GetAllowedBinariesSha256(),
			MaxOpenCount:          req.GetMaxOpenCount(),
			Writable:              req.GetWritable(),
			Measure:               req.GetMeasure(),
		},
		req.GetPlaintextData(),
	)

	if err := p.baselineStore.Save(bl); err != nil {
		logger.Error("Failed to save baseline for %s: %v", targetPath, err)
		return nil, status.Error(codes.Internal, "failed to save baseline")
	}

	rule, _ := bl.Rule()
	logger.Info("[OnboardFile] sha=%s path=%s strategy=%s", shaIdentifier, targetPath, rule.VerificationStrategy)
	logger.Debug("[OnboardFile] sha=%s allowed_binaries=%v perms={UID:%d,GID:%d,MODE:%#o} max_open=%d writable=%v measure=%v",
		shaIdentifier,
		rule.AllowedPrograms,
		filePermsUID(perms), filePermsGID(perms), filePermsMode(perms),
		rule.MaxOpenCount,
		rule.Writable,
		rule.Measure)

	return &enclave.StatusResponse{
		Success: true,
		Message: "File onboarded successfully",
		Sha:     shaIdentifier,
	}, nil
}

// ─── FilePerms nil-safe helpers ───────────────────────────────────────────────

func filePermsUID(p *baseline.FilePerms) uint32 {
	if p == nil {
		return 0
	}
	return p.UID
}
func filePermsGID(p *baseline.FilePerms) uint32 {
	if p == nil {
		return 0
	}
	return p.GID
}
func filePermsMode(p *baseline.FilePerms) uint32 {
	if p == nil {
		return 0
	}
	return p.Mode
}

// generateUniqueSha generates a unique SHA identifier by checking for conflicts.
func (p *PolicyEngine) generateUniqueSha(baseSha string) string {
	if p.baselineStore.GetBySha(baseSha) == nil {
		return baseSha
	}
	for i := 1; i <= 100; i++ {
		suffix := fmt.Sprintf("-%d", i)
		newSha := baseSha
		if len(newSha)+len(suffix) > 12 {
			newSha = baseSha[:12-len(suffix)]
		}
		newSha += suffix
		if p.baselineStore.GetBySha(newSha) == nil {
			return newSha
		}
	}
	ts := fmt.Sprintf("%s-%d", baseSha[:8], time.Now().UnixNano()%10000)
	if len(ts) > 12 {
		ts = ts[:12]
	}
	logger.Warn("Failed to generate unique SHA after 100 attempts, using timestamp-based suffix: %s", ts)
	return ts
}

// ReleaseFile releases a credential file from the enclave.
func (p *PolicyEngine) ReleaseFile(ctx context.Context, req *enclave.ReleaseFileRequest) (*enclave.ReleaseFileResponse, error) {
	fileID := req.GetFileId()
	bl := p.baselineStore.GetBySha(fileID)
	if bl == nil {
		return &enclave.ReleaseFileResponse{Success: false, Message: "Baseline not found"},
			status.Error(codes.NotFound, "Baseline not found")
	}

	password := req.GetPassword()
	if password == "" {
		logger.Warn("Password required to release file %s", bl.Metadata().TargetPath)
		return nil, status.Error(codes.InvalidArgument, "Password required")
	}
	if !p.verifyUserPassword(req.GetUid(), password) {
		logger.Warn("Incorrect password provided by user %d for releasing file %s", req.GetUid(), bl.Metadata().TargetPath)
		return nil, status.Error(codes.PermissionDenied, "Incorrect password")
	}

	plainText, err := bl.FileContent()
	if err != nil {
		logger.Error("Failed to load file content for release: %v", err)
		return nil, status.Error(codes.Internal, "failed to load file content")
	}

	meta := bl.Metadata()
	finalTargetPath := meta.TargetPath

	var uid, gid, mode uint32
	if meta.Permissions != nil {
		uid = meta.Permissions.UID
		gid = meta.Permissions.GID
		mode = meta.Permissions.Mode
	} else {
		uid = uint32(os.Getuid())
		gid = uint32(os.Getgid())
		mode = 0600
	}

	logger.Info("Successfully prepared credential for release for %s by user %d", finalTargetPath, req.GetUid())
	return &enclave.ReleaseFileResponse{
		Success:     true,
		Message:     "File release data retrieved successfully",
		FilePath:    finalTargetPath,
		FileContent: plainText,
		OwnerUid:    uid,
		OwnerGid:    gid,
		Permission:  mode,
		FileId:      bl.SHA(),
	}, nil
}

// RemoveFile removes a protected file from the baseline by its SHA identifier.
func (p *PolicyEngine) RemoveFile(ctx context.Context, req *enclave.RemoveFileRequest) (*enclave.StatusResponse, error) {
	sha := req.GetSha()
	password := req.GetPassword()

	logger.Info("Attempting to remove protected file by SHA: %s", sha)

	bl := p.baselineStore.GetBySha(sha)
	if bl == nil {
		logger.Warn("File not found in baseline with SHA: %s", sha)
		return &enclave.StatusResponse{
			Success: false,
			Message: fmt.Sprintf("File with SHA %s not found in baseline", sha),
		}, nil
	}

	if !p.verifyUserPassword(0, password) {
		logger.Warn("Invalid password provided for removing file with SHA %s", sha)
		return &enclave.StatusResponse{Success: false, Message: "Invalid password"}, nil
	}

	filePath := bl.Metadata().TargetPath

	if err := p.baselineStore.Delete(sha); err != nil {
		logger.Error("Failed to delete baseline record for file %s (SHA: %s): %v", filePath, sha, err)
		return &enclave.StatusResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to delete baseline record: %v", err),
		}, nil
	}

	logger.Info("Successfully removed baseline for protected file: %s (SHA: %s)", filePath, sha)
	return &enclave.StatusResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully removed baseline for protected file: %s", filePath),
	}, nil
}

// DumpFileContent retrieves the plaintext content of a protected file without modifying the baseline.
func (p *PolicyEngine) DumpFileContent(ctx context.Context, req *enclave.DumpFileContentRequest) (*enclave.DumpFileContentResponse, error) {
	sha := req.GetSha()
	password := req.GetPassword()

	if password == "" {
		return nil, status.Error(codes.InvalidArgument, "Password required")
	}

	bl := p.baselineStore.GetBySha(sha)
	if bl == nil {
		return nil, status.Error(codes.NotFound, "Baseline not found")
	}

	if !p.verifyUserPassword(0, password) {
		return nil, status.Error(codes.PermissionDenied, "Incorrect password")
	}

	content, err := bl.FileContent()
	if err != nil {
		logger.Error("Failed to load file content for dump: %v", err)
		return nil, status.Error(codes.Internal, "failed to load file content")
	}

	logger.Info("Successfully dumped credential content for %s", bl.Metadata().TargetPath)
	return &enclave.DumpFileContentResponse{
		Success:    true,
		Message:    "File content retrieved successfully",
		Content:    content,
		TargetPath: bl.Metadata().TargetPath,
	}, nil
}

// RestoreFileContent replaces the content of a protected file with new data.
func (p *PolicyEngine) RestoreFileContent(ctx context.Context, req *enclave.RestoreFileContentRequest) (*enclave.RestoreFileContentResponse, error) {
	sha := req.GetSha()
	password := req.GetPassword()
	newContent := req.GetContent()

	if password == "" {
		return nil, status.Error(codes.InvalidArgument, "Password required")
	}

	bl := p.baselineStore.GetBySha(sha)
	if bl == nil {
		return nil, status.Error(codes.NotFound, "Baseline not found")
	}

	if !p.verifyUserPassword(0, password) {
		return nil, status.Error(codes.PermissionDenied, "Incorrect password")
	}

	bl.SetFileContent(newContent)
	meta := bl.Metadata()
	meta.Size = int64(len(newContent))
	bl.SetMetadata(meta)

	if err := p.baselineStore.Save(bl); err != nil {
		logger.Error("Failed to save restored content for %s: %v", meta.TargetPath, err)
		return nil, status.Error(codes.Internal, "failed to save restored content")
	}

	logger.Info("Successfully restored credential content for %s (new size: %d)", meta.TargetPath, len(newContent))
	return &enclave.RestoreFileContentResponse{
		Success: true,
		Message: "File content restored successfully",
		NewSize: int64(len(newContent)),
	}, nil
}

// ─── MonitorGuardService ──────────────────────────────────────────────────────

// RequestFUSEAccess checks if a process is allowed to access a credential file.
func (p *PolicyEngine) RequestFUSEAccess(ctx context.Context, objectPath string, process osutil.ProcessInf, req *FUSEAccessRequest) (*enclave.AccessResponse, error) {
	pid := process.GetPid()
	logger.Debug("RequestFUSEAccess called. ObjectPath: %s, PID: %d, AccessMode: %s",
		objectPath, pid, req.AccessMode.String())

	briefCmd := osutil.BriefCmdline(process.GetCmdline())

	// Step 1: Baseline lookup.
	logger.Debug("Step 1: Checking baseline for object path: %s", objectPath)
	bl := p.baselineStore.GetBySha(objectPath)
	if bl == nil {
		logger.Debug("SHA lookup failed for %s, trying target path lookup", objectPath)
		bl = p.baselineStore.Get(objectPath)
	}
	if bl == nil {
		logger.Warn("[denied] Object:%s, Program: %s, Reason: No baseline found for the requested object.", objectPath, briefCmd)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: "No baseline found for the requested object.",
		}, nil
	}

	rule, err := bl.Rule()
	if err != nil {
		logger.Error("Failed to load rule for sha=%s: %v", bl.SHA(), err)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: "Failed to load security rule.",
		}, nil
	}

	logger.Debug("Found baseline for %s. Verification strategy: %s, Allowed binaries: %v, SHA: %s",
		objectPath, rule.VerificationStrategy, rule.AllowedPrograms, bl.SHA())

	// Step 2: File permissions check.
	uid := process.GetUid()
	gid := process.GetGid()

	logger.Debug("Step 2: Checking file permissions. Process UID: %d, GID: %d, AccessMode: %s",
		uid, gid, req.AccessMode.String())

	meta := bl.Metadata()
	var protoPerms *enclave.FilePerms
	if meta.Permissions != nil {
		protoPerms = &enclave.FilePerms{
			Uid:  meta.Permissions.UID,
			Gid:  meta.Permissions.GID,
			Mode: meta.Permissions.Mode,
		}
	}

	if !checkPermissionsWithAccessMode(uid, gid, protoPerms, req.AccessMode) {
		logger.Warn("[denied] Object:%s, Program: %s, Reason: User does not have permission for file with mode %o, UID %d, GID %d, AccessMode: %s",
			objectPath, briefCmd,
			protoPerms.GetMode(), protoPerms.GetUid(), protoPerms.GetGid(), req.AccessMode.String())
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: fmt.Sprintf("User does not have %s permission based on original file mode.", req.AccessMode.String()),
		}, nil
	}

	// Step 3: SHA256 integrity check (only when Measure is enabled).
	logger.Debug("Step 3: Checking allowed binaries SHA256 (measure=%v).", rule.Measure)
	if rule.Measure && len(rule.AllowedProgramsSha256) > 0 {
		exeSha, err := process.GetSha256()
		if err != nil {
			logger.Error("RequestFUSEAccess: failed to compute SHA256 for PID %d: %v", pid, err)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
				DenialReason: "Failed to compute program checksum.",
			}, nil
		}
		if !isHashInList(exeSha, rule.AllowedProgramsSha256) {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Program checksum mismatch. Expected: %v, Actual: %s",
				objectPath, briefCmd, rule.AllowedProgramsSha256, exeSha)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
				DenialReason: "Program checksum mismatch.",
			}, nil
		}
	}

	// Step 4: Open count limit check.
	logger.Debug("Step 4: Checking open count limit. Current open count for PID %d accessing %s: %d, Max allowed: %d",
		pid, objectPath, req.CurrentOpenCount, rule.MaxOpenCount)

	if rule.MaxOpenCount > 0 && req.CurrentOpenCount >= rule.MaxOpenCount {
		logger.Warn("[denied] Object:%s, Program: %s, Reason: Open count limit exceeded. Have opened: %d, Max allowed: %d",
			objectPath, briefCmd, req.CurrentOpenCount, rule.MaxOpenCount)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: fmt.Sprintf("Open count limit exceeded. Have opened: %d, Max: %d", req.CurrentOpenCount, rule.MaxOpenCount),
		}, nil
	}

	// Step 5: Process risk check (anti-debug, injection, env vars, ancestor chain - all unified).
	// Inject this credential's authorized binaries into the trusted list so the
	// requesting process and any ancestors that happen to be authorized pass
	// Binary.CheckRisk regardless of install location.
	logger.Debug("Step 5: Checking process risk. PID: %d", pid)
	riskCfg := p.riskCheckConfig.WithTrustedPrograms(rule.AllowedPrograms)
	if riskResult := process.CheckRisk(riskCfg); riskResult.Level == osutil.Untrusted {
		logger.Warn("[denied] Object:%s, Program: %s, Reason: %s",
			objectPath, briefCmd, riskResult.Reason)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: riskResult.Reason,
		}, nil
	}

	// Step 6: Verification strategy.
	logger.Debug("Step 6: Processing verification strategy: %s", rule.VerificationStrategy)
	switch rule.VerificationStrategy {
	case "BASIC":
		logger.Debug("PID %d accessing %s is permitted", pid, objectPath)
		return p.approveAccess(bl, rule, req.AccessMode)

	case "ONE_TIME_USE":
		uuid := process.GetEnvVar("CRED_PERMIT_UUID")
		if uuid == "" {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: A valid permit UUID is required for strategy %s but none provided",
				objectPath, briefCmd, rule.VerificationStrategy)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: "A valid permit UUID is required for this strategy.",
			}, nil
		}
		ticket, exists := p.findTicketByUUID(uuid)
		if !exists {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Ticket not found for UUID %s in strategy %s",
				objectPath, briefCmd, uuid, rule.VerificationStrategy)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Ticket not found for UUID %s", uuid),
			}, nil
		}
		if ticket.GetStatus() == "BURNED" {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Ticket has been burned for UUID %s",
				objectPath, briefCmd, uuid)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Ticket has been burned for UUID %s", uuid),
			}, nil
		}
		cmdline := process.GetCmdline()
		if ticket.GetCommandSpec() != "" {
			if !p.isCommandSpecMatching(ticket.GetCommandSpec(), cmdline) {
				logger.Warn("[denied] Object:%s, Program: %s, Reason: Command spec mismatch for UUID %s. Expected: %s, Actual: %s",
					objectPath, briefCmd, uuid, ticket.GetCommandSpec(), briefCmd)
				return &enclave.AccessResponse{
					Status:       enclave.AccessStatus_ACCESS_PERMIT_DENIED,
					DenialReason: fmt.Sprintf("Command spec mismatch. Expected: %s, Actual: %s", ticket.GetCommandSpec(), cmdline),
				}, nil
			}
		} else {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Command spec is empty for ticket UUID %s (retry mechanism triggered)",
				objectPath, briefCmd, uuid)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Command spec is empty for ticket UUID %s (retry mechanism triggered)", uuid),
			}, nil
		}
		p.ledgerStore.ConsumeTicket(uuid, pid, rule.VerificationStrategy)
		return p.approveAccess(bl, rule, req.AccessMode)

	case "PID_BIND":
		uuid := process.GetEnvVar("CRED_PERMIT_UUID")
		if uuid == "" {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: A valid permit UUID is required for strategy %s but none provided",
				objectPath, briefCmd, rule.VerificationStrategy)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: "A valid permit UUID is required for this strategy.",
			}, nil
		}
		ticket, exists := p.findTicketByUUID(uuid)
		if !exists {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Ticket not found for UUID %s in strategy %s",
				objectPath, briefCmd, uuid, rule.VerificationStrategy)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Ticket not found for UUID %s", uuid),
			}, nil
		}
		if ticket.GetStatus() == "BURNED" {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Ticket has been burned for UUID %s",
				objectPath, briefCmd, uuid)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Ticket has been burned for UUID %s", uuid),
			}, nil
		}
		if ticket.GetStatus() == "PENDING" {
			updatedTicket := &enclave.PermitTicket{
				Uuid:           ticket.GetUuid(),
				TargetFilePath: ticket.GetTargetFilePath(),
				Status:         "ACTIVE",
				CommandSpec:    ticket.GetCommandSpec(),
				BoundPid:       int64(pid),
				ExpiresAt:      ticket.GetExpiresAt(),
			}
			p.ledgerStore.AddTicket(updatedTicket)
			logger.Debug("First access for ticket %s, bound to PID %d and transitioned to ACTIVE", uuid, pid)
			return p.approveAccess(bl, rule, req.AccessMode)
		}
		cmdline := process.GetCmdline()
		if ticket.GetCommandSpec() != "" {
			if !p.isCommandSpecMatching(ticket.GetCommandSpec(), cmdline) {
				logger.Warn("[denied] Object:%s, Program: %s, Reason: Command spec mismatch for UUID %s. Expected: %s, Actual: %s",
					objectPath, briefCmd, uuid, ticket.GetCommandSpec(), briefCmd)
				return &enclave.AccessResponse{
					Status:       enclave.AccessStatus_ACCESS_PERMIT_DENIED,
					DenialReason: fmt.Sprintf("Command spec mismatch. Expected: %s, Actual: %s", ticket.GetCommandSpec(), cmdline),
				}, nil
			}
		} else {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: Command spec is empty for ticket UUID %s (retry mechanism triggered)",
				objectPath, briefCmd, uuid)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("Command spec is empty for ticket UUID %s (retry mechanism triggered)", uuid),
			}, nil
		}
		if ticket.GetStatus() != "PENDING" && ticket.GetBoundPid() != 0 && int64(ticket.GetBoundPid()) != int64(pid) {
			logger.Warn("[denied] Object:%s, Program: %s, Reason: TOCTOU attack detected: PID mismatch for ticket %s. Expected PID: %d, Actual PID: %d.",
				objectPath, briefCmd, uuid, ticket.GetBoundPid(), pid)
			p.ledgerStore.ConsumeTicket(uuid, pid, rule.VerificationStrategy)
			return &enclave.AccessResponse{
				Status:       enclave.AccessStatus_ACCESS_NO_PERMIT_TICKET,
				DenialReason: fmt.Sprintf("TOCTOU attack detected: PID mismatch for ticket %s. Ticket has been burned for security.", uuid),
			}, nil
		}
		result := p.ledgerStore.ConsumeTicket(uuid, pid, rule.VerificationStrategy)
		if result.Success {
			if currentTicket, exists := p.ledgerStore.GetTicket(uuid); exists {
				updatedTicket := &enclave.PermitTicket{
					Uuid:           currentTicket.GetUuid(),
					TargetFilePath: currentTicket.GetTargetFilePath(),
					Status:         "ACTIVE",
					CommandSpec:    currentTicket.GetCommandSpec(),
					BoundPid:       int64(pid),
					ExpiresAt:      currentTicket.GetExpiresAt(),
				}
				p.ledgerStore.AddTicket(updatedTicket)
			}
		}
		return p.approveAccess(bl, rule, req.AccessMode)

	case "SPEC_VERIFICATION":
		logger.Debug("Processing SPEC_VERIFICATION cmd spec")
		cmdline := process.GetCmdline()
		return p.handleSpecBasedVerificationV2(objectPath, cmdline, bl, rule, req.AccessMode)

	default:
		logger.Error("[denied] Object:%s, Program: %s, Reason: Unknown verification strategy in baseline: %s",
			objectPath, briefCmd, rule.VerificationStrategy)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: "Unknown verification strategy in baseline.",
		}, nil
	}
}


// ListProtectedFiles returns metadata for all protected files (no file content).
func (p *PolicyEngine) ListProtectedFiles(ctx context.Context, req *emptypb.Empty) (*enclave.ListProtectedFilesResponse, error) {
	allBaselines := p.baselineStore.ListAll()
	logger.Debug("Found %d protected files", len(allBaselines))

	safeBaselines := make([]*enclave.CredentialBaseline, 0, len(allBaselines))
	for _, bl := range allBaselines {
		safeBaselines = append(safeBaselines, toProtoBaseline(bl))
	}

	return &enclave.ListProtectedFilesResponse{
		Success:   true,
		Message:   fmt.Sprintf("Retrieved %d protected files", len(safeBaselines)),
		Baselines: safeBaselines,
	}, nil
}

// CheckFileExistence checks if a file exists in the baseline without full access authorisation.
func (p *PolicyEngine) CheckFileExistence(ctx context.Context, procCtx *enclave.ProcessContext) (*enclave.FileExistenceResponse, error) {
	logger.Debug("Checking baseline for object path: %s", procCtx.GetObjectPath())

	bl := p.baselineStore.GetBySha(procCtx.GetObjectPath())
	if bl == nil {
		logger.Debug("SHA lookup failed for %s, trying target path lookup", procCtx.GetObjectPath())
		bl = p.baselineStore.Get(procCtx.GetObjectPath())
	}

	if bl != nil {
		meta := bl.Metadata()
		var protoPerms *enclave.FilePerms
		if meta.Permissions != nil {
			protoPerms = &enclave.FilePerms{
				Uid:  meta.Permissions.UID,
				Gid:  meta.Permissions.GID,
				Mode: meta.Permissions.Mode,
			}
		}
		logger.Debug("Found baseline for %s. SHA: %s, TargetPath: %s", procCtx.GetObjectPath(), bl.SHA(), meta.TargetPath)
		return &enclave.FileExistenceResponse{
			Exists:       true,
			IsProtected:  true,
			Sha:          bl.SHA(),
			TargetPath:   meta.TargetPath,
			Permissions:  protoPerms,
			CreationTime: meta.Ctime,
			Size:         meta.Size,
			DenialReason: "",
		}, nil
	}

	logger.Debug("No baseline found for object path: %s", procCtx.GetObjectPath())
	return &enclave.FileExistenceResponse{
		Exists:       false,
		IsProtected:  false,
		DenialReason: "No baseline found for the requested object.",
	}, nil
}

// AddPermitTicket adds a permit ticket to the ledger.
func (p *PolicyEngine) AddPermitTicket(ctx context.Context, ticket *enclave.PermitTicket) (*enclave.StatusResponse, error) {
	logger.Info("Adding permit ticket to ledger. UUID: %s, TargetFile: %s, Status: %s",
		ticket.GetUuid(), ticket.GetTargetFilePath(), ticket.GetStatus())

	if ticket.GetUuid() == "" {
		return &enclave.StatusResponse{Success: false, Message: "Ticket UUID cannot be empty"}, nil
	}
	if ticket.GetTargetFilePath() == "" {
		return &enclave.StatusResponse{Success: false, Message: "Ticket target file path cannot be empty"}, nil
	}

	if err := p.ledgerStore.AddTicket(ticket); err != nil {
		logger.Error("Failed to add ticket to ledger: %v", err)
		return &enclave.StatusResponse{Success: false, Message: fmt.Sprintf("Failed to add ticket to ledger: %v", err)}, nil
	}

	logger.Info("Successfully added permit ticket to ledger. UUID: %s", ticket.GetUuid())
	return &enclave.StatusResponse{Success: true, Message: "Permit ticket added successfully"}, nil
}

// RequestPermission handles requests for permission to access a credential file.
func (p *PolicyEngine) RequestPermission(ctx context.Context, req *enclave.RequestPermissionRequest) (*enclave.RequestPermissionResponse, error) {
	logger.Info("Received permission request. Intent: %s, Cmdline: %s, TargetFile: %s",
		req.GetIntent(), req.GetCmdline(), req.GetTargetFile())

	intent := req.GetIntent()
	cmdline := req.GetCmdline()
	targetFile := req.GetTargetFile()

	auditResponse, err := p.credAgentClient.AuditCommandWithTargetFile(cmdline, intent, targetFile)

	if err != nil || (auditResponse != nil &&
		(strings.Contains(auditResponse.Reason, "CredAgent is not properly configured") ||
			strings.Contains(auditResponse.Reason, "Failed to communicate with AI model"))) {

		logger.Warn("CredAgent audit failed or not properly configured. Using internal logic as fallback.")
		internalResponse := p.credAgentClient.InternalAuditLogic(intent, cmdline)
		if internalResponse.Decision == "ALLOW" {
			return p.createPermitTicketResponse(cmdline, targetFile)
		}
		logger.Warn("Internal audit logic DENY: %s", internalResponse.Reason)
		return &enclave.RequestPermissionResponse{
			Success:  false,
			Message:  fmt.Sprintf("Access denied by internal audit: %s", internalResponse.Reason),
			Decision: "DENY",
		}, nil
	}

	if auditResponse.Decision == "ALLOW" {
		return p.createPermitTicketResponse(cmdline, targetFile)
	}
	logger.Warn("CredAgent denied access. Reason: %s", auditResponse.Reason)
	return &enclave.RequestPermissionResponse{
		Success:  false,
		Message:  fmt.Sprintf("Access denied by CredAgent: %s", auditResponse.Reason),
		Decision: "DENY",
	}, nil
}

func (p *PolicyEngine) createPermitTicketResponse(cmdline, targetFile string) (*enclave.RequestPermissionResponse, error) {
	uuid := p.generateUUID()
	ticket := &enclave.PermitTicket{
		Uuid:           uuid,
		TargetFilePath: targetFile,
		Status:         "ACTIVE",
		CommandSpec:    cmdline,
	}
	if err := p.ledgerStore.AddTicket(ticket); err != nil {
		logger.Error("Failed to add ticket to ledger: %v", err)
		return &enclave.RequestPermissionResponse{Success: false, Message: fmt.Sprintf("Failed to create permit ticket: %v", err), Decision: "DENY"}, nil
	}
	logger.Info("Successfully created permit ticket. UUID: %s, TargetFile: %s", uuid, targetFile)
	return &enclave.RequestPermissionResponse{
		Success:  true,
		Message:  fmt.Sprintf("Access granted. A permit ticket has been created. You can now access the file '%s' by re-executing the same command with the CRED_PERMIT_UUID environment variable set to '%s'.\n\nREMEMBER: Keep the command parameters identical to the original request, otherwise access will be denied.", targetFile, uuid),
		Uuid:     uuid,
		Decision: "ALLOW",
	}, nil
}

// UpdateFileInfo updates the security configuration of an existing protected file.
func (p *PolicyEngine) UpdateFileInfo(ctx context.Context, req *enclave.UpdateFileAccessRule) (*enclave.UpdateFileInfoResponse, error) {
	logger.Debug("Received UpdateFileInfo request for SHA: %s", req.GetSha())

	if !p.verifyUserPassword(0, req.GetPassword()) {
		logger.Warn("Invalid password for UpdateFileInfo request")
		return &enclave.UpdateFileInfoResponse{Success: false, Message: "Invalid password"}, nil
	}

	bl := p.baselineStore.GetBySha(req.GetSha())
	if bl == nil {
		logger.Warn("Baseline not found for SHA: %s", req.GetSha())
		return &enclave.UpdateFileInfoResponse{Success: false, Message: "Baseline not found"}, nil
	}

	rule, err := bl.Rule()
	if err != nil {
		logger.Warn("Failed to load rule for SHA %s: %v", req.GetSha(), err)
		return &enclave.UpdateFileInfoResponse{Success: false, Message: "Failed to load security rule"}, nil
	}
	if rule == nil {
		rule = &baseline.AccessRule{}
	}

	// Apply only the fields that were explicitly flagged for update.
	if req.GetStrategy() != "" {
		rule.VerificationStrategy = req.GetStrategy()
	}
	if req.GetUpdateAllowedBinaries() {
		rule.AllowedPrograms = req.GetAllowedBinaries()
		rule.AllowedProgramsSha256 = req.GetAllowedBinariesSha256()
	}
	if req.GetUpdateMeasure() {
		rule.Measure = req.GetMeasure()
	}
	if req.GetUpdateMaxOpenCount() {
		rule.MaxOpenCount = req.GetMaxOpenCount()
	}
	if req.GetUpdateWritable() {
		rule.Writable = req.GetWritable()
	}

	bl.SetRule(rule)

	if err := p.baselineStore.Set(bl.Metadata().TargetPath, bl); err != nil {
		logger.Error("Failed to update baseline for SHA %s: %v", req.GetSha(), err)
		return &enclave.UpdateFileInfoResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to update baseline: %v", err),
		}, nil
	}

	logger.Info("[UpdateFileInfo] sha=%s strategy=%s measure=%v", req.GetSha(), rule.VerificationStrategy, rule.Measure)
	return &enclave.UpdateFileInfoResponse{
		Success:         true,
		Message:         "Access rules updated successfully",
		UpdatedBaseline: toProtoBaseline(bl),
	}, nil
}

// AttachPrograms adds new allowed Program programs to an existing protected file.
// Programs already present are skipped; the response reports both added and skipped lists.
func (p *PolicyEngine) AttachPrograms(ctx context.Context, req *enclave.AttachProgramsRequest) (*enclave.AttachProgramsResponse, error) {
	logger.Debug("[AttachPrograms] sha=%s candidates=%v", req.GetSha(), req.GetAllowedBinaries())

	// Validate that both arrays are the same length to guarantee index correspondence.
	if len(req.GetAllowedBinaries()) != len(req.GetAllowedBinariesSha256()) {
		return &enclave.AttachProgramsResponse{
			Success: false,
			Message: fmt.Sprintf("allowed_binaries (%d) and allowed_binaries_sha256 (%d) must have the same length",
				len(req.GetAllowedBinaries()), len(req.GetAllowedBinariesSha256())),
		}, nil
	}

	if !p.verifyUserPassword(0, req.GetPassword()) {
		logger.Warn("Invalid password for AttachPrograms request")
		return &enclave.AttachProgramsResponse{Success: false, Message: "Invalid password"}, nil
	}

	bl := p.baselineStore.GetBySha(req.GetSha())
	if bl == nil {
		logger.Warn("[AttachPrograms] Baseline not found for SHA: %s", req.GetSha())
		return &enclave.AttachProgramsResponse{Success: false, Message: "Baseline not found"}, nil
	}

	rule, err := bl.Rule()
	if err != nil {
		logger.Warn("[AttachPrograms] Failed to load rule for SHA %s: %v", req.GetSha(), err)
		return &enclave.AttachProgramsResponse{Success: false, Message: "Failed to load security rule"}, nil
	}
	if rule == nil {
		rule = &baseline.AccessRule{}
	}

	// Build a set of existing programs for O(1) lookup.
	existingSet := make(map[string]struct{}, len(rule.AllowedPrograms))
	for _, prog := range rule.AllowedPrograms {
		existingSet[prog] = struct{}{}
	}

	var added, skipped []string
	sha256List := req.GetAllowedBinariesSha256()
	for i, binary := range req.GetAllowedBinaries() {
		if _, exists := existingSet[binary]; exists {
			skipped = append(skipped, binary)
			continue
		}
		rule.AllowedPrograms = append(rule.AllowedPrograms, binary)
		rule.AllowedProgramsSha256 = append(rule.AllowedProgramsSha256, sha256List[i])
		existingSet[binary] = struct{}{}
		added = append(added, binary)
	}

	if len(added) == 0 {
		logger.Info("[AttachPrograms] sha=%s no new programs to add; all %d skipped", req.GetSha(), len(skipped))
		return &enclave.AttachProgramsResponse{
			Success:         true,
			Message:         fmt.Sprintf("No new programs added; %d already exist", len(skipped)),
			Skipped:         skipped,
			UpdatedBaseline: toProtoBaseline(bl),
		}, nil
	}

	bl.SetRule(rule)
	if err := p.baselineStore.Set(bl.Metadata().TargetPath, bl); err != nil {
		logger.Error("[AttachPrograms] Failed to save baseline for SHA %s: %v", req.GetSha(), err)
		return &enclave.AttachProgramsResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to save baseline: %v", err),
		}, nil
	}

	logger.Info("[AttachPrograms] sha=%s added=%v skipped=%v", req.GetSha(), added, skipped)
	return &enclave.AttachProgramsResponse{
		Success:         true,
		Message:         fmt.Sprintf("Added %d program(s), skipped %d", len(added), len(skipped)),
		Added:           added,
		Skipped:         skipped,
		UpdatedBaseline: toProtoBaseline(bl),
	}, nil
}

// DetachPrograms removes allowed binary programs from an existing protected file.
// Each program is removed by its path; the paired SHA256 at the same index is removed simultaneously.
// Programs not found in the allowed list are reported in the not_found list but do not fail the operation.
func (p *PolicyEngine) DetachPrograms(ctx context.Context, req *enclave.DetachProgramsRequest) (*enclave.DetachProgramsResponse, error) {
	logger.Debug("[DetachPrograms] sha=%s candidates=%v", req.GetSha(), req.GetAllowedBinaries())

	if !p.verifyUserPassword(0, req.GetPassword()) {
		logger.Warn("Invalid password for DetachPrograms request")
		return &enclave.DetachProgramsResponse{Success: false, Message: "Invalid password"}, nil
	}

	bl := p.baselineStore.GetBySha(req.GetSha())
	if bl == nil {
		logger.Warn("[DetachPrograms] Baseline not found for SHA: %s", req.GetSha())
		return &enclave.DetachProgramsResponse{Success: false, Message: "Baseline not found"}, nil
	}

	rule, err := bl.Rule()
	if err != nil {
		logger.Warn("[DetachPrograms] Failed to load rule for SHA %s: %v", req.GetSha(), err)
		return &enclave.DetachProgramsResponse{Success: false, Message: "Failed to load security rule"}, nil
	}
	if rule == nil {
		rule = &baseline.AccessRule{}
	}

	// Build a set of programs to remove for O(1) lookup.
	removeSet := make(map[string]struct{}, len(req.GetAllowedBinaries()))
	for _, binary := range req.GetAllowedBinaries() {
		removeSet[binary] = struct{}{}
	}

	// Rebuild both arrays, removing paired entries at matching indices.
	removedSet := make(map[string]struct{})
	var newPrograms, newSha256 []string
	for i, prog := range rule.AllowedPrograms {
		if _, shouldRemove := removeSet[prog]; shouldRemove {
			removedSet[prog] = struct{}{}
			continue // skip both the program and its paired sha256
		}
		newPrograms = append(newPrograms, prog)
		if i < len(rule.AllowedProgramsSha256) {
			newSha256 = append(newSha256, rule.AllowedProgramsSha256[i])
		}
	}

	// Classify request entries into removed vs not_found.
	var removed, notFound []string
	for _, binary := range req.GetAllowedBinaries() {
		if _, wasRemoved := removedSet[binary]; wasRemoved {
			removed = append(removed, binary)
		} else {
			notFound = append(notFound, binary)
		}
	}

	if len(removed) == 0 {
		logger.Info("[DetachPrograms] sha=%s nothing removed; all %d not found", req.GetSha(), len(notFound))
		return &enclave.DetachProgramsResponse{
			Success:         true,
			Message:         fmt.Sprintf("Nothing removed; %d program(s) not found in allowed list", len(notFound)),
			NotFound:        notFound,
			UpdatedBaseline: toProtoBaseline(bl),
		}, nil
	}

	rule.AllowedPrograms = newPrograms
	rule.AllowedProgramsSha256 = newSha256
	bl.SetRule(rule)

	if err := p.baselineStore.Set(bl.Metadata().TargetPath, bl); err != nil {
		logger.Error("[DetachPrograms] Failed to save baseline for SHA %s: %v", req.GetSha(), err)
		return &enclave.DetachProgramsResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to save baseline: %v", err),
		}, nil
	}

	logger.Info("[DetachPrograms] sha=%s removed=%v not_found=%v", req.GetSha(), removed, notFound)
	return &enclave.DetachProgramsResponse{
		Success:         true,
		Message:         fmt.Sprintf("Removed %d program(s), %d not found", len(removed), len(notFound)),
		Removed:         removed,
		NotFound:        notFound,
		UpdatedBaseline: toProtoBaseline(bl),
	}, nil
}

// RefreshPrograms updates SHA256 values for programs already present in an existing protected file.
// Programs not in the allowed list are reported in not_authorized and skipped without modification.
// The SHA256 is updated in-place at the exact index matching the program in AllowedPrograms,
// preserving strict 1:1 index correspondence.
func (p *PolicyEngine) RefreshPrograms(ctx context.Context, req *enclave.RefreshProgramsRequest) (*enclave.RefreshProgramsResponse, error) {
	logger.Debug("[RefreshPrograms] sha=%s candidates=%v", req.GetSha(), req.GetAllowedBinaries())

	// Validate that both input arrays have the same length to guarantee index correspondence.
	if len(req.GetAllowedBinaries()) != len(req.GetAllowedBinariesSha256()) {
		return &enclave.RefreshProgramsResponse{
			Success: false,
			Message: fmt.Sprintf("allowed_binaries (%d) and allowed_binaries_sha256 (%d) must have the same length",
				len(req.GetAllowedBinaries()), len(req.GetAllowedBinariesSha256())),
		}, nil
	}

	if !p.verifyUserPassword(0, req.GetPassword()) {
		logger.Warn("Invalid password for RefreshPrograms request")
		return &enclave.RefreshProgramsResponse{Success: false, Message: "Invalid password"}, nil
	}

	bl := p.baselineStore.GetBySha(req.GetSha())
	if bl == nil {
		logger.Warn("[RefreshPrograms] Baseline not found for SHA: %s", req.GetSha())
		return &enclave.RefreshProgramsResponse{Success: false, Message: "Baseline not found"}, nil
	}

	rule, err := bl.Rule()
	if err != nil {
		logger.Warn("[RefreshPrograms] Failed to load rule for SHA %s: %v", req.GetSha(), err)
		return &enclave.RefreshProgramsResponse{Success: false, Message: "Failed to load security rule"}, nil
	}
	if rule == nil {
		rule = &baseline.AccessRule{}
	}

	// Build a map from program path → its index in AllowedPrograms for O(1) lookup.
	programIndex := make(map[string]int, len(rule.AllowedPrograms))
	for i, prog := range rule.AllowedPrograms {
		programIndex[prog] = i
	}

	// Copy existing SHA256 slice; update entries at matched indices.
	newSha256 := make([]string, len(rule.AllowedPrograms))
	copy(newSha256, rule.AllowedProgramsSha256)

	var refreshed, notAuthorized []string
	sha256List := req.GetAllowedBinariesSha256()
	for i, binary := range req.GetAllowedBinaries() {
		if idx, found := programIndex[binary]; found {
			newSha256[idx] = sha256List[i]
			refreshed = append(refreshed, binary)
		} else {
			notAuthorized = append(notAuthorized, binary)
		}
	}

	if len(refreshed) == 0 {
		logger.Info("[RefreshPrograms] sha=%s nothing refreshed; all %d not authorized", req.GetSha(), len(notAuthorized))
		return &enclave.RefreshProgramsResponse{
			Success:         true,
			Message:         fmt.Sprintf("Nothing refreshed; %d program(s) not in allowed list", len(notAuthorized)),
			NotAuthorized:   notAuthorized,
			UpdatedBaseline: toProtoBaseline(bl),
		}, nil
	}

	rule.AllowedProgramsSha256 = newSha256
	bl.SetRule(rule)

	if err := p.baselineStore.Set(bl.Metadata().TargetPath, bl); err != nil {
		logger.Error("[RefreshPrograms] Failed to save baseline for SHA %s: %v", req.GetSha(), err)
		return &enclave.RefreshProgramsResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to save baseline: %v", err),
		}, nil
	}

	logger.Info("[RefreshPrograms] sha=%s refreshed=%v not_authorized=%v", req.GetSha(), refreshed, notAuthorized)
	return &enclave.RefreshProgramsResponse{
		Success:         true,
		Message:         fmt.Sprintf("Refreshed %d program(s), %d not authorized", len(refreshed), len(notAuthorized)),
		Refreshed:       refreshed,
		NotAuthorized:   notAuthorized,
		UpdatedBaseline: toProtoBaseline(bl),
	}, nil
}

// GetProtectedFileInfo retrieves information about a specific protected file by SHA.
func (p *PolicyEngine) GetProtectedFileInfo(ctx context.Context, req *enclave.GetProtectedFileInfoRequest) (*enclave.GetProtectedFileInfoResponse, error) {
	bl := p.baselineStore.GetBySha(req.GetSha())
	if bl == nil {
		logger.Warn("File not found in baseline with SHA: %s", req.GetSha())
		return &enclave.GetProtectedFileInfoResponse{
			Success: false,
			Message: fmt.Sprintf("File with SHA %s not found in baseline", req.GetSha()),
		}, nil
	}

	logger.Debug("Successfully retrieved information for protected file: %s (SHA: %s)", bl.Metadata().TargetPath, bl.SHA())
	return &enclave.GetProtectedFileInfoResponse{
		Success:  true,
		Message:  fmt.Sprintf("Successfully retrieved information for protected file with SHA: %s", req.GetSha()),
		Baseline: toProtoBaseline(bl),
	}, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// approveAccess prepares a successful access response after policy checks pass.
// Write permission and truncation are handled by the FUSE layer directly.
func (p *PolicyEngine) approveAccess(bl *baseline.CredentialBaseline, rule *baseline.AccessRule, accessMode enclave.AccessMode) (*enclave.AccessResponse, error) {
	isWriteMode := accessMode == enclave.AccessMode_WRITE_ONLY || accessMode == enclave.AccessMode_READ_WRITE

	if isWriteMode && !rule.Writable {
		logger.Warn("[denied] Object:%s, Reason: Baseline does not allow write operations (Writable=false)", bl.SHA())
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_BASELINE_DENIED,
			DenialReason: "This credential file is read-only (Writable=false in baseline).",
		}, nil
	}

	return &enclave.AccessResponse{
		Status:       enclave.AccessStatus_ACCESS_GRANTED,
		FileSha:      bl.SHA(),
		MaxOpenCount: rule.MaxOpenCount,
	}, nil
}

// handleSpecBasedVerificationV2 performs SPEC_VERIFICATION strategy access check.
func (p *PolicyEngine) handleSpecBasedVerificationV2(objectPath, cmdline string, bl *baseline.CredentialBaseline, rule *baseline.AccessRule, accessMode enclave.AccessMode) (*enclave.AccessResponse, error) {
	logger.Info("Performing real-time SPEC verification with handle management for command: %s", osutil.BriefCmdline(cmdline))

	realTargetPath := bl.Metadata().TargetPath
	logger.Info("Using real target path from baseline: %s (was hash: %s)", realTargetPath, objectPath)

	auditResponse, err := p.credAgentClient.AuditCommandWithTargetFile(cmdline, "Real-time FUSE access request for "+realTargetPath, realTargetPath)

	logger.Debug("CredAgent audit response: Decision=%s, Reason=%s, Confidence=%.2f",
		auditResponse.Decision, auditResponse.Reason, auditResponse.Confidence)

	if err != nil || (auditResponse != nil &&
		(strings.Contains(auditResponse.Reason, "CredAgent is not properly configured") ||
			strings.Contains(auditResponse.Reason, "Failed to communicate with AI model"))) {

		logger.Warn("CredAgent audit failed or not properly configured. Using internal logic as fallback.")
		internalResponse := p.credAgentClient.InternalAuditLogic("Real-time FUSE access request for "+realTargetPath, cmdline)
		if internalResponse.Decision == "ALLOW" {
			logger.Info("Internal audit logic allowed access for command: %s", osutil.BriefCmdline(cmdline))
			return p.approveAccess(bl, rule, accessMode)
		}
		logger.Warn("Internal audit logic denied access for command: %s. Reason: %s", osutil.BriefCmdline(cmdline), internalResponse.Reason)
		return &enclave.AccessResponse{
			Status:       enclave.AccessStatus_ACCESS_PERMIT_DENIED,
			DenialReason: fmt.Sprintf("Internal audit rejected: %s", internalResponse.Reason),
		}, nil
	}

	if auditResponse.Decision == "ALLOW" {
		logger.Info("CredAgent approved access for command: %s", osutil.BriefCmdline(cmdline))
		return p.approveAccess(bl, rule, accessMode)
	}
	logger.Warn("[denied] Object:%s, Program: %s, Reason: CredAgent denied access: %s",
		objectPath, osutil.BriefCmdline(cmdline), auditResponse.Reason)
	return &enclave.AccessResponse{
		Status:       enclave.AccessStatus_ACCESS_PERMIT_DENIED,
		DenialReason: fmt.Sprintf("CredAgent denied access: %s", auditResponse.Reason),
	}, nil
}

func (p *PolicyEngine) findTicketByUUID(uuid string) (*enclave.PermitTicket, bool) {
	return p.ledgerStore.GetTicket(uuid)
}

func (p *PolicyEngine) isCommandSpecMatching(expected, actual string) bool {
	expectedCmd, expectedParams := parseCommandToParams(expected)
	actualCmd, actualParams := parseCommandToParams(actual)
	if expectedCmd != actualCmd {
		return false
	}
	for _, ep := range expectedParams {
		found := false
		for _, ap := range actualParams {
			if ep == ap {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func parseCommandToParams(cmdLine string) (string, []string) {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return "", []string{}
	}
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return "", []string{}
	}
	return parts[0], parts[1:]
}

func (p *PolicyEngine) generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("ticket_%d", len(p.ledgerStore.ListTickets()))
	}
	return hex.EncodeToString(b)
}

func (p *PolicyEngine) verifyUserPassword(uid int32, password string) bool {
	if p.adminPasswordStore == nil {
		logger.Error("Admin password store is not initialized")
		return false
	}
	return p.adminPasswordStore.VerifyPassword(password)
}

func isHashInList(hash string, hashes []string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}

func checkPermissionsWithAccessMode(uid int32, gid int32, perms *enclave.FilePerms, accessMode enclave.AccessMode) bool {
	if perms == nil {
		return false
	}
	mode := perms.GetMode()
	fileUID := perms.GetUid()
	fileGID := perms.GetGid()

	const (
		readOwner  = 1 << 8
		writeOwner = 1 << 7
		readGroup  = 1 << 5
		writeGroup = 1 << 4
		readOther  = 1 << 2
		writeOther = 1 << 1
	)

	var hasRead, hasWrite bool
	if uid == 0 {
		hasRead, hasWrite = true, true
	} else if uint32(uid) == fileUID {
		hasRead = (mode & readOwner) != 0
		hasWrite = (mode & writeOwner) != 0
	} else if uint32(gid) == fileGID {
		hasRead = (mode & readGroup) != 0
		hasWrite = (mode & writeGroup) != 0
	} else {
		hasRead = (mode & readOther) != 0
		hasWrite = (mode & writeOther) != 0
	}

	switch accessMode {
	case enclave.AccessMode_READ_WRITE:
		return hasRead && hasWrite
	case enclave.AccessMode_WRITE_ONLY:
		return hasWrite
	default:
		return hasRead
	}
}
