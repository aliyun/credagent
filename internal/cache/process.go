package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/pkg/logger"
)

var globalActiveHandles int64

// GlobalActiveHandleCount returns the total number of active FUSE file handles across all processes.
func GlobalActiveHandleCount() int64 {
	return atomic.LoadInt64(&globalActiveHandles)
}

// ProcessInf extends osutil.ProcessInf with lifecycle state management.
// FUSE modules should depend on this interface rather than the concrete Process type.
type ProcessInf interface {
	osutil.ProcessInf
	IsUntrusted() bool
	MarkUntrusted(reason string)
	GetOpenCount(objectPath string) int64
	IncrementOpenCount(objectPath string)
	IncrementActiveHandle(objectPath string)
	DecrementActiveHandle(objectPath string)
	MarkActive()
}

// Pid is a convenience method for backward compatibility.
func (p *Process) Pid() int32 { return p.ProcessInf.GetPid() }

// GetBriefCmdline returns a brief version of the process cmdline (for logging).
func (p *Process) GetBriefCmdline() string {
	return osutil.BriefCmdline(p.ProcessInf.GetCmdline())
}

// ObjectAccessState tracks per-object access state for a process.
type ObjectAccessState struct {
	openCount         int64
	activeHandleCount int64
}

// Process wraps an osutil.ProcessInf with lifecycle and per-object access state.
// It embeds ProcessInf so callers can use it wherever ProcessInf is expected.
type Process struct {
	osutil.ProcessInf
	mu          sync.Mutex
	objects     map[string]*ObjectAccessState
	deactiveAt      time.Time
	untrusted       bool
	untrustedReason string
}

func (p *Process) UnwrapProcess() *osutil.Process {
	if proc, ok := p.ProcessInf.(*osutil.Process); ok {
		return proc
	}
	return nil
}

func (p *Process) IsHarnessed() bool {
	if proc := p.UnwrapProcess(); proc != nil {
		return proc.IsHarnessed()
	}
	return false
}

func (p *Process) IsUntrusted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.untrusted
}

func (p *Process) MarkUntrusted(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.untrusted = true
	p.untrustedReason = reason
}

func (p *Process) GetOpenCount(objectPath string) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if oas, ok := p.objects[objectPath]; ok {
		return oas.openCount
	}
	return 0
}

func (p *Process) IncrementOpenCount(objectPath string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getOrCreateObject(objectPath).openCount++
}

func (p *Process) IncrementActiveHandle(objectPath string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getOrCreateObject(objectPath).activeHandleCount++
	atomic.AddInt64(&globalActiveHandles, 1)
}

func (p *Process) DecrementActiveHandle(objectPath string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	oas, ok := p.objects[objectPath]
	if !ok {
		return
	}
	if oas.activeHandleCount > 0 {
		oas.activeHandleCount--
		atomic.AddInt64(&globalActiveHandles, -1)
		logger.Debug("[cache.DecrementActiveHandle] pid=%d obj=%s handles=%d", p.Pid(), objectPath, oas.activeHandleCount)
	}
	if p.totalActiveHandlesLocked() == 0 {
		p.deactiveAt = time.Now()
		logger.Debug("[cache.DecrementActiveHandle] DEACTIVATE pid=%d (all handles released)", p.Pid())
	}
}

func (p *Process) TotalActiveHandles() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalActiveHandlesLocked()
}

func (p *Process) totalActiveHandlesLocked() int64 {
	var total int64
	for _, oas := range p.objects {
		total += oas.activeHandleCount
	}
	return total
}

func (p *Process) MarkActive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deactiveAt = time.Time{}
}

func (p *Process) IsExpired(timeout time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deactiveAt.IsZero() {
		return false
	}
	return time.Since(p.deactiveAt) > timeout
}

func (p *Process) getOrCreateObject(objectPath string) *ObjectAccessState {
	oas, ok := p.objects[objectPath]
	if !ok {
		oas = &ObjectAccessState{}
		p.objects[objectPath] = oas
	}
	return oas
}

// --- Global process table ---

var (
	processTable      = make(map[uint32]*Process)
	processTableMu    sync.RWMutex
	fdShareCheckEnabled bool = false
)

// InitFdShareCheck sets whether cross-process fd share detection is active.
func InitFdShareCheck(enabled bool) {
	fdShareCheckEnabled = enabled
}

// FdShareCheckEnabled returns the current fd_share_check setting.
func FdShareCheckEnabled() bool {
	return fdShareCheckEnabled
}

// processFactory creates an osutil.ProcessInf for a given PID.
// Override via SetProcessFactory in tests.
var processFactory = func(pid int32) osutil.ProcessInf {
	return osutil.NewProcess(pid)
}

// SetProcessFactory overrides the function used to create ProcessInf instances.
// For testing only.
func SetProcessFactory(f func(pid int32) osutil.ProcessInf) {
	processFactory = f
}

// GetOrCreate looks up the Process for the given PID.
// On cache miss or PID reuse (detected via IsSame), creates a new entry.
func GetOrCreate(pid uint32) *Process {
	processTableMu.RLock()
	ps, exists := processTable[pid]
	processTableMu.RUnlock()

	if exists {
		info := processFactory(int32(pid))
		if ps.ProcessInf.IsSame(info) {
			logger.Debug("[cache.GetOrCreate] HIT pid=%d (table=%d)", pid, len(processTable))
			return ps
		}

		processTableMu.Lock()
		defer processTableMu.Unlock()

		ps, exists = processTable[pid]
		if exists && ps.ProcessInf.IsSame(info) {
			logger.Debug("[cache.GetOrCreate] HIT-RACE pid=%d", pid)
			return ps
		}

		logger.Debug("[cache.GetOrCreate] PID-REUSE pid=%d (old st=%d, new st=%d), replacing", pid, ps.GetStartTime(), info.GetStartTime())

		ps = &Process{
			ProcessInf: info,
			objects:    make(map[string]*ObjectAccessState),
		}
		processTable[pid] = ps
		return ps
	}

	info := processFactory(int32(pid))

	processTableMu.Lock()
	defer processTableMu.Unlock()

	ps, exists = processTable[pid]
	if exists && ps.ProcessInf.IsSame(info) {
		logger.Debug("[cache.GetOrCreate] HIT-RACE pid=%d", pid)
		return ps
	}

	ps = &Process{
		ProcessInf: info,
		objects:    make(map[string]*ObjectAccessState),
	}
	processTable[pid] = ps
	logger.Debug("[cache.GetOrCreate] MISS pid=%d (table now=%d)", pid, len(processTable))
	return ps
}

// GetOrTouch is the entry point for ancestor-chain caching. Unlike GetOrCreate
// (used by FUSE entry, which leaves deactiveAt at zero meaning "never expires
// until DecrementActiveHandle"), GetOrTouch refreshes deactiveAt = time.Now()
// so an ancestor entry that nobody is actively using gets garbage-collected
// after the standard cleanup timeout.
//
// FUSE-active entries (deactiveAt == zero) are NOT touched; the FUSE layer
// retains its lifecycle control over them.
func GetOrTouch(pid uint32) *Process {
	ps := GetOrCreate(pid)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// Only refresh expiration on entries that are not FUSE-active.
	// A zero deactiveAt means either (a) FUSE-active with live handles, or
	// (b) brand-new entry just created. Case (b) we still want to mark as
	// soft-cached so it can expire; we use the presence of any objects/handles
	// to detect case (a).
	if !ps.deactiveAt.IsZero() || ps.totalActiveHandlesLocked() == 0 {
		ps.deactiveAt = time.Now()
		logger.Debug("[cache.GetOrTouch] REFRESH pid=%d deactiveAt=now (ancestor cache)", pid)
	} else {
		logger.Debug("[cache.GetOrTouch] SKIP-REFRESH pid=%d (FUSE-active)", pid)
	}
	return ps
}

// ancestorProvider adapts cache.GetOrTouch to the osutil.ProcessProvider
// interface so osutil.Process.GetParent can use the shared cache.
type ancestorProvider struct{}

func (ancestorProvider) GetOrTouchProcess(pid uint32) osutil.ProcessInf {
	return GetOrTouch(pid)
}

// NewProcessProvider returns a ProcessProvider backed by this cache.
// Register it once at startup via osutil.SetProcessProvider.
func NewProcessProvider() osutil.ProcessProvider {
	return ancestorProvider{}
}

// GetByPid returns the Process for the given PID, or nil if not found.
func GetByPid(pid uint32) *Process {
	processTableMu.RLock()
	defer processTableMu.RUnlock()
	return processTable[pid]
}

// TableSize returns the current size of the global process table.
func TableSize() int {
	processTableMu.RLock()
	defer processTableMu.RUnlock()
	return len(processTable)
}

// ResetTable clears the global process table. For testing only.
func ResetTable() {
	processTableMu.Lock()
	defer processTableMu.Unlock()
	processTable = make(map[uint32]*Process)
}

// StartCleanup starts a background goroutine that periodically removes
// expired entries. Returns a stop function.
func StartCleanup(cleanupTimeout time.Duration) func() {
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				logger.Info("cache cleanup goroutine stopped")
				return
			case <-ticker.C:
				cleanupExpired(cleanupTimeout)
			}
		}
	}()
	logger.Info("cache cleanup goroutine started (timeout=%v)", cleanupTimeout)
	return func() { close(stopCh) }
}

func cleanupExpired(timeout time.Duration) {
	processTableMu.Lock()
	defer processTableMu.Unlock()

	var removed int
	for pid, ps := range processTable {
		if ps.IsExpired(timeout) {
			logger.Debug("[cache.cleanup] EVICT pid=%d (idle>timeout)", pid)
			delete(processTable, pid)
			removed++
		}
	}
	if removed > 0 {
		logger.Debug("[cache.cleanup] removed=%d remaining=%d", removed, len(processTable))
	}
}
