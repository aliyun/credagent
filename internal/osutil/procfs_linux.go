//go:build linux

package osutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// getSystemBootTime returns the system boot time in seconds since epoch.
func getSystemBootTime() (uint64, error) {
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				bootTime, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return bootTime, nil
			}
		}
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

// GetProcessStartTime returns the start time of a process in seconds since epoch.
func GetProcessStartTime(pid uint32) (uint64, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	content, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		return 0, fmt.Errorf("not enough fields in stat file")
	}
	startTime, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0, err
	}
	bootTime, err := getSystemBootTime()
	if err != nil {
		return 0, err
	}
	return bootTime + uint64(float64(startTime)/100.0), nil
}
