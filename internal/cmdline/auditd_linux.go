//go:build linux

package cmdline

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
)

const (
	auditKey             = "credagent_cmdline"
	auditLogPath         = "/var/log/audit/audit.log"
	cacheCleanupInterval = 30 * time.Second
	entryMaxAge          = 60 * time.Second
)

var interpreterDirs = []string{"/usr/bin", "/usr/local/bin"}

// Patterns match basename of real interpreter binaries only.
// e.g. python3, python3.11, perl, perl5.36.3, ruby, ruby3.2, node, php, php8.1, java
var interpreterNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^python[0-9.]*$`),
	regexp.MustCompile(`^perl[0-9.]*$`),
	regexp.MustCompile(`^ruby[0-9.]*$`),
	regexp.MustCompile(`^node[0-9.]*$`),
	regexp.MustCompile(`^php[0-9.]*$`),
	regexp.MustCompile(`^java$`),
}

type auditEntry struct {
	cmdline   string
	timestamp float64
}

type auditdSource struct {
	cache            sync.Map // map[uint32]*auditEntry
	rules            []string // exe paths we added rules for (for cleanup)
	removedTaskNever bool     // whether we removed the "task,never" rule (restore on close)
	tailCmd          *exec.Cmd
	mu               sync.Mutex
	stopCh           chan struct{}
	wg               sync.WaitGroup
}

func newAuditdSource() (*auditdSource, error) {
	if err := checkAuditdRunning(); err != nil {
		return nil, err
	}

	removedTaskNever := removeTaskNeverRule()

	paths := discoverInterpreterPaths()
	if len(paths) == 0 {
		if removedTaskNever {
			restoreTaskNeverRule()
		}
		return nil, fmt.Errorf("no interpreters found on system")
	}
	logger.Info("auditd: discovered %d interpreter paths", len(paths))

	addedRules := ensureAuditRules(paths)
	if len(addedRules) == 0 {
		if removedTaskNever {
			restoreTaskNeverRule()
		}
		return nil, fmt.Errorf("failed to add any audit rules")
	}

	s := &auditdSource{
		rules:           addedRules,
		removedTaskNever: removedTaskNever,
		stopCh:          make(chan struct{}),
	}

	if err := s.startTail(); err != nil {
		s.cleanupRules()
		return nil, fmt.Errorf("failed to start audit log tail: %w", err)
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	return s, nil
}

func (s *auditdSource) Name() string   { return "auditd" }
func (s *auditdSource) Available() bool { return true }

func (s *auditdSource) Lookup(pid uint32) (string, bool) {
	val, ok := s.cache.Load(pid)
	if !ok {
		return "", false
	}
	entry := val.(*auditEntry)

	startTime, err := osutil.GetProcessStartTime(pid)
	if err != nil {
		// Process may have exited; discard stale entry
		s.cache.Delete(pid)
		return "", false
	}
	if math.Abs(entry.timestamp-float64(startTime)) > 2.0 {
		s.cache.Delete(pid)
		return "", false
	}
	return entry.cmdline, true
}

func (s *auditdSource) Close() {
	close(s.stopCh)
	s.mu.Lock()
	if s.tailCmd != nil && s.tailCmd.Process != nil {
		s.tailCmd.Process.Kill()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.cleanupRules()
	if s.removedTaskNever {
		restoreTaskNeverRule()
	}
}

// --- Initialization helpers ---

func checkAuditdRunning() error {
	out, err := exec.Command("auditctl", "-s").CombinedOutput()
	if err != nil {
		return fmt.Errorf("auditctl -s failed: %w (is auditd installed?)", err)
	}
	if !strings.Contains(string(out), "enabled") {
		return fmt.Errorf("audit subsystem not enabled")
	}
	// Check for "enabled 1" or "enabled 2"
	if strings.Contains(string(out), "enabled 0") {
		return fmt.Errorf("audit subsystem disabled (enabled 0)")
	}
	return nil
}

// removeTaskNeverRule removes the "-a task,never" rule that suppresses all
// syscall auditing. Our execve rules must be added AFTER this removal so
// that newly forked processes have proper audit context.
func removeTaskNeverRule() bool {
	out, _ := exec.Command("auditctl", "-l").CombinedOutput()
	if !strings.Contains(string(out), "-a never,task") && !strings.Contains(string(out), "-a task,never") {
		return false
	}
	err := exec.Command("auditctl", "-d", "task,never").Run()
	if err != nil {
		logger.Warn("auditd: failed to remove task,never rule: %v", err)
		return false
	}
	logger.Info("auditd: removed rule: -a task,never (to enable syscall auditing for new processes)")
	return true
}

func restoreTaskNeverRule() {
	err := exec.Command("auditctl", "-a", "task,never").Run()
	if err != nil {
		logger.Warn("auditd: failed to restore task,never rule: %v", err)
	} else {
		logger.Info("auditd: restored rule: -a task,never")
	}
}

func discoverInterpreterPaths() []string {
	seen := make(map[string]bool)
	var result []string

	for _, dir := range interpreterDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !matchesInterpreterName(name) {
				continue
			}
			fullPath := filepath.Join(dir, name)
			real, err := filepath.EvalSymlinks(fullPath)
			if err != nil {
				continue
			}
			if seen[real] {
				continue
			}
			fi, err := os.Stat(real)
			if err != nil || fi.IsDir() {
				continue
			}
			if fi.Mode()&0111 == 0 {
				continue
			}
			seen[real] = true
			result = append(result, real)
		}
	}
	return result
}

func matchesInterpreterName(name string) bool {
	for _, pat := range interpreterNamePatterns {
		if pat.MatchString(name) {
			return true
		}
	}
	return false
}

func ensureAuditRules(paths []string) []string {
	// Clean up stale rules with our key first (from a previous crash without cleanup).
	// Then add fresh rules — they must be created AFTER task,never removal.
	cleanupStaleRules()

	var added []string
	for _, p := range paths {
		err := exec.Command("auditctl", "-a", "always,exit",
			"-F", "arch=b64", "-S", "execve",
			"-F", "exe="+p, "-k", auditKey).Run()
		if err != nil {
			logger.Warn("auditd: failed to add rule for exe=%s: %v", p, err)
			continue
		}
		added = append(added, p)
		logger.Info("auditd: added rule: -a always,exit -F arch=b64 -S execve -F exe=%s -k %s", p, auditKey)
	}
	return added
}

// cleanupStaleRules removes any pre-existing rules with our key (left over from a crash).
func cleanupStaleRules() {
	out, err := exec.Command("auditctl", "-l").CombinedOutput()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, auditKey) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "exe=") {
				exe := strings.TrimPrefix(field, "exe=")
				delErr := exec.Command("auditctl", "-d", "always,exit",
					"-F", "arch=b64", "-S", "execve",
					"-F", "exe="+exe, "-k", auditKey).Run()
				if delErr != nil {
					logger.Warn("auditd: failed to remove stale rule for exe=%s: %v", exe, delErr)
				} else {
					logger.Info("auditd: removed stale rule: -d always,exit -F exe=%s -k %s", exe, auditKey)
				}
			}
		}
	}
}

func (s *auditdSource) cleanupRules() {
	for _, p := range s.rules {
		err := exec.Command("auditctl", "-d", "always,exit",
			"-F", "arch=b64", "-S", "execve",
			"-F", "exe="+p, "-k", auditKey).Run()
		if err != nil {
			logger.Warn("auditd: failed to remove rule for exe=%s: %v", p, err)
		} else {
			logger.Info("auditd: removed rule: -d always,exit -F arch=b64 -S execve -F exe=%s -k %s", p, auditKey)
		}
	}
}

// --- Tail and parsing ---

const tailRestartDelay = 2 * time.Second

func (s *auditdSource) startTail() error {
	if _, err := os.Stat(auditLogPath); err != nil {
		return fmt.Errorf("audit log not found: %s", auditLogPath)
	}

	s.wg.Add(1)
	go s.tailLoop()
	return nil
}

// tailLoop manages the tail|grep pipeline lifecycle, restarting on exit.
func (s *auditdSource) tailLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		cmd := s.launchTailPipeline()
		if cmd == nil {
			select {
			case <-s.stopCh:
				return
			case <-time.After(tailRestartDelay):
				continue
			}
		}

		s.mu.Lock()
		s.tailCmd = cmd
		s.mu.Unlock()

		// Wait for the pipeline to exit
		cmd.Wait()

		s.mu.Lock()
		s.tailCmd = nil
		s.mu.Unlock()

		select {
		case <-s.stopCh:
			return
		default:
			logger.Warn("auditd: tail pipeline exited, restarting in %v", tailRestartDelay)
			select {
			case <-s.stopCh:
				return
			case <-time.After(tailRestartDelay):
			}
		}
	}
}

// launchTailPipeline starts "tail -n 0 -F <log> | grep --line-buffered <filter>"
// and feeds the output to parseLines. Returns the tail cmd (the pipeline owner).
func (s *auditdSource) launchTailPipeline() *exec.Cmd {
	// Filter: our key (in SYSCALL lines) OR EXECVE type (carries argv, linked by event ID)
	filter := fmt.Sprintf(`key="%s"\|type=EXECVE`, auditKey)
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf(`tail -n 0 -F %s | grep --line-buffered '%s'`, auditLogPath, filter))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Warn("auditd: failed to create stdout pipe: %v", err)
		return nil
	}
	if err := cmd.Start(); err != nil {
		logger.Warn("auditd: failed to start tail pipeline: %v", err)
		return nil
	}

	go s.parseLines(bufio.NewScanner(stdout))
	return cmd
}

// Regex patterns for parsing audit log lines
var (
	reMsgTimestamp = regexp.MustCompile(`msg=audit\(([0-9.]+):\d+\)`)
	rePidField     = regexp.MustCompile(`\bpid=(\d+)`)
	reArgField     = regexp.MustCompile(`\ba(\d+)=("(?:[^"\\]|\\.)*"|[0-9A-Fa-f]+)`)
	reKeyField     = regexp.MustCompile(`\bkey="([^"]*)"`)
)

// parseLines reads filtered audit log lines and extracts execve events.
// Audit events come as multiple lines with the same timestamp:serial.
// We track state across SYSCALL + EXECVE line pairs.
func (s *auditdSource) parseLines(scanner *bufio.Scanner) {
	type pendingEvent struct {
		pid       uint32
		timestamp float64
		args      map[int]string
	}

	pending := make(map[string]*pendingEvent)

	for scanner.Scan() {
		select {
		case <-s.stopCh:
			return
		default:
		}

		line := scanner.Text()

		msgMatch := reMsgTimestamp.FindStringSubmatch(line)
		if msgMatch == nil {
			continue
		}
		eventID := msgMatch[0]
		ts, _ := strconv.ParseFloat(msgMatch[1], 64)

		if strings.HasPrefix(line, "type=SYSCALL") {
			keyMatch := reKeyField.FindStringSubmatch(line)
			if keyMatch == nil || keyMatch[1] != auditKey {
				continue
			}
			pidMatch := rePidField.FindStringSubmatch(line)
			if pidMatch == nil {
				continue
			}
			pid, _ := strconv.ParseUint(pidMatch[1], 10, 32)
			pending[eventID] = &pendingEvent{
				pid:       uint32(pid),
				timestamp: ts,
				args:      make(map[int]string),
			}
		} else if strings.HasPrefix(line, "type=EXECVE") {
			evt, ok := pending[eventID]
			if !ok {
				continue
			}
			for _, match := range reArgField.FindAllStringSubmatch(line, -1) {
				idx, _ := strconv.Atoi(match[1])
				val := decodeAuditArg(match[2])
				evt.args[idx] = val
			}
			cmdline := buildCmdline(evt.args)
			if cmdline != "" {
				s.cache.Store(evt.pid, &auditEntry{
					cmdline:   cmdline,
					timestamp: evt.timestamp,
				})
			}
			delete(pending, eventID)
		}

		if len(pending) > 1000 {
			for k := range pending {
				delete(pending, k)
				if len(pending) <= 500 {
					break
				}
			}
		}
	}
}

func decodeAuditArg(raw string) string {
	if strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"") {
		// Quoted string — remove quotes and unescape
		s := raw[1 : len(raw)-1]
		s = strings.ReplaceAll(s, "\\\"", "\"")
		s = strings.ReplaceAll(s, "\\\\", "\\")
		return s
	}
	// Hex-encoded string
	decoded, err := hexDecode(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func hexDecode(s string) (string, error) {
	if len(s)%2 != 0 {
		return "", fmt.Errorf("odd length hex string")
	}
	var buf []byte
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return "", err
		}
		buf = append(buf, byte(b))
	}
	return string(buf), nil
}

func buildCmdline(args map[int]string) string {
	if len(args) == 0 {
		return ""
	}
	// Find max index
	maxIdx := 0
	for k := range args {
		if k > maxIdx {
			maxIdx = k
		}
	}
	parts := make([]string, 0, maxIdx+1)
	for i := 0; i <= maxIdx; i++ {
		if v, ok := args[i]; ok {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

// cleanupLoop periodically removes stale cache entries.
func (s *auditdSource) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(cacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := float64(time.Now().Unix())
			s.cache.Range(func(key, value any) bool {
				entry := value.(*auditEntry)
				if now-entry.timestamp > entryMaxAge.Seconds() {
					s.cache.Delete(key)
				}
				return true
			})
		}
	}
}
