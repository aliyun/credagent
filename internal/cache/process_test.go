package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/aliyun/credagent/internal/osutil"
)

func mockFactory(registry map[int32]osutil.ProcessInf) func(pid int32) osutil.ProcessInf {
	return func(pid int32) osutil.ProcessInf {
		if p, ok := registry[pid]; ok {
			return p
		}
		return osutil.NewMockProcess(pid)
	}
}

func TestGetOrCreate_NewProcess(t *testing.T) {
	ResetTable()

	mock := osutil.NewMockProcess(100, osutil.WithStartTime(1000))
	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{100: mock}))

	ps := GetOrCreate(100)

	if ps == nil {
		t.Fatal("expected non-nil Process")
	}
	if ps.Pid() != 100 {
		t.Errorf("expected pid 100, got %d", ps.Pid())
	}
	if ps.GetStartTime() != 1000 {
		t.Errorf("expected startTime 1000, got %d", ps.GetStartTime())
	}
	if ps.ProcessInf != mock {
		t.Error("expected embedded ProcessInf to be the same mock")
	}
	if TableSize() != 1 {
		t.Errorf("expected table size 1, got %d", TableSize())
	}
}

func TestGetOrCreate_SameProcess(t *testing.T) {
	ResetTable()

	mock := osutil.NewMockProcess(100, osutil.WithStartTime(1000))
	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{100: mock}))

	ps1 := GetOrCreate(100)
	ps2 := GetOrCreate(100)

	if ps1 != ps2 {
		t.Error("expected same Process for same PID+startTime")
	}
	if TableSize() != 1 {
		t.Errorf("expected table size 1, got %d", TableSize())
	}
}

func TestGetOrCreate_PIDReuse(t *testing.T) {
	ResetTable()

	registry := map[int32]osutil.ProcessInf{
		100: osutil.NewMockProcess(100, osutil.WithStartTime(1000)),
	}
	SetProcessFactory(mockFactory(registry))

	psOld := GetOrCreate(100)
	psOld.IncrementOpenCount("obj1")

	registry[100] = osutil.NewMockProcess(100, osutil.WithStartTime(2000))

	psNew := GetOrCreate(100)

	if psNew == psOld {
		t.Error("expected new Process after PID reuse")
	}
	if psNew.GetStartTime() != 2000 {
		t.Errorf("expected startTime 2000, got %d", psNew.GetStartTime())
	}
	if psNew.GetOpenCount("obj1") != 0 {
		t.Errorf("expected openCount 0 for new process, got %d", psNew.GetOpenCount("obj1"))
	}
	if TableSize() != 1 {
		t.Errorf("expected table size 1, got %d", TableSize())
	}
}

func TestOpenCountAndActiveHandle(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		200: osutil.NewMockProcess(200, osutil.WithStartTime(5000)),
	}))
	ps := GetOrCreate(200)

	if ps.GetOpenCount("fileA") != 0 {
		t.Errorf("expected initial openCount 0, got %d", ps.GetOpenCount("fileA"))
	}
	if ps.TotalActiveHandles() != 0 {
		t.Errorf("expected initial totalActiveHandles 0, got %d", ps.TotalActiveHandles())
	}

	for i := 0; i < 3; i++ {
		ps.IncrementOpenCount("fileA")
		ps.IncrementActiveHandle("fileA")
	}

	if ps.GetOpenCount("fileA") != 3 {
		t.Errorf("expected openCount 3, got %d", ps.GetOpenCount("fileA"))
	}
	if ps.TotalActiveHandles() != 3 {
		t.Errorf("expected totalActiveHandles 3, got %d", ps.TotalActiveHandles())
	}

	ps.DecrementActiveHandle("fileA")
	ps.DecrementActiveHandle("fileA")

	if ps.GetOpenCount("fileA") != 3 {
		t.Errorf("openCount should stay at 3, got %d", ps.GetOpenCount("fileA"))
	}
	if ps.TotalActiveHandles() != 1 {
		t.Errorf("expected totalActiveHandles 1, got %d", ps.TotalActiveHandles())
	}
}

func TestMultipleObjects(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		300: osutil.NewMockProcess(300, osutil.WithStartTime(6000)),
	}))
	ps := GetOrCreate(300)

	ps.IncrementOpenCount("fileA")
	ps.IncrementActiveHandle("fileA")
	ps.IncrementOpenCount("fileB")
	ps.IncrementActiveHandle("fileB")

	if ps.TotalActiveHandles() != 2 {
		t.Errorf("expected totalActiveHandles 2, got %d", ps.TotalActiveHandles())
	}

	ps.DecrementActiveHandle("fileA")
	if ps.TotalActiveHandles() != 1 {
		t.Errorf("expected totalActiveHandles 1 after releasing fileA, got %d", ps.TotalActiveHandles())
	}

	ps.DecrementActiveHandle("fileB")
	if ps.TotalActiveHandles() != 0 {
		t.Errorf("expected totalActiveHandles 0, got %d", ps.TotalActiveHandles())
	}
	if ps.IsExpired(1 * time.Hour) {
		t.Error("should not be expired yet (timeout is 1h)")
	}
	if !ps.IsExpired(0) {
		t.Error("should be expired with timeout=0")
	}
}

func TestDeactiveAndCleanup(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		400: osutil.NewMockProcess(400, osutil.WithStartTime(7000)),
	}))
	ps := GetOrCreate(400)
	ps.IncrementActiveHandle("file1")
	ps.DecrementActiveHandle("file1")

	if TableSize() != 1 {
		t.Fatalf("expected table size 1, got %d", TableSize())
	}

	cleanupExpired(0)

	if TableSize() != 0 {
		t.Errorf("expected table size 0 after cleanup, got %d", TableSize())
	}
}

func TestDeactiveReactivate(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		500: osutil.NewMockProcess(500, osutil.WithStartTime(8000)),
	}))
	ps := GetOrCreate(500)

	ps.IncrementActiveHandle("file1")
	ps.DecrementActiveHandle("file1")

	ps.IncrementActiveHandle("file1")
	ps.MarkActive()

	cleanupExpired(0)

	if TableSize() != 1 {
		t.Errorf("expected table size 1 (reactivated), got %d", TableSize())
	}
}

func TestCleanupOnlyExpired(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		600: osutil.NewMockProcess(600, osutil.WithStartTime(9000)),
		601: osutil.NewMockProcess(601, osutil.WithStartTime(9001)),
	}))

	psA := GetOrCreate(600)
	psA.IncrementActiveHandle("f1")
	psA.DecrementActiveHandle("f1")

	psB := GetOrCreate(601)
	psB.IncrementActiveHandle("f2")
	_ = psB

	if TableSize() != 2 {
		t.Fatalf("expected table size 2, got %d", TableSize())
	}

	cleanupExpired(0)

	if TableSize() != 1 {
		t.Errorf("expected table size 1 (only active process), got %d", TableSize())
	}
}

func TestDecrementActiveHandleBelowZero(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		700: osutil.NewMockProcess(700, osutil.WithStartTime(10000)),
	}))
	ps := GetOrCreate(700)

	ps.DecrementActiveHandle("file1")
	if ps.TotalActiveHandles() != 0 {
		t.Errorf("expected totalActiveHandles 0, got %d", ps.TotalActiveHandles())
	}
}

func TestBlacklist(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		800: osutil.NewMockProcess(800, osutil.WithStartTime(11000)),
	}))
	ps := GetOrCreate(800)

	if ps.IsUntrusted() {
		t.Error("expected not untrusted initially")
	}

	ps.MarkUntrusted("cross-process fd share detected")

	if !ps.IsUntrusted() {
		t.Error("expected untrusted after MarkUntrusted")
	}
}

func TestGetByPid(t *testing.T) {
	ResetTable()

	if GetByPid(999) != nil {
		t.Error("expected nil for unknown PID")
	}

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		900: osutil.NewMockProcess(900, osutil.WithStartTime(12000)),
	}))
	ps := GetOrCreate(900)

	found := GetByPid(900)
	if found != ps {
		t.Error("expected GetByPid to return the same Process")
	}
}

func TestGetOrCreate_Concurrent(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		42: osutil.NewMockProcess(42, osutil.WithStartTime(9999)),
	}))

	var wg sync.WaitGroup
	results := make([]*Process, 10)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = GetOrCreate(42)
		}(i)
	}
	wg.Wait()

	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Fatal("concurrent GetOrCreate returned different Process instances for same PID")
		}
	}
}

func TestProcessImplementsProcessInf(t *testing.T) {
	ResetTable()

	SetProcessFactory(mockFactory(map[int32]osutil.ProcessInf{
		50: osutil.NewMockProcess(50,
			osutil.WithStartTime(1234),
			osutil.WithUid(1000),
			osutil.WithCmdline("/usr/bin/test --flag"),
		),
	}))
	ps := GetOrCreate(50)

	var inf osutil.ProcessInf = ps
	if inf.GetPid() != 50 {
		t.Errorf("expected Pid 50, got %d", inf.GetPid())
	}
	if inf.GetStartTime() != 1234 {
		t.Errorf("expected startTime 1234, got %d", inf.GetStartTime())
	}
	if inf.GetUid() != 1000 {
		t.Errorf("expected uid 1000, got %d", inf.GetUid())
	}
	if inf.GetCmdline() != "/usr/bin/test --flag" {
		t.Errorf("unexpected cmdline: %s", inf.GetCmdline())
	}
}
