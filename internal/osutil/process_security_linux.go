//go:build linux

package osutil

// getNativeDangerousPrefixes returns environment variable prefixes that indicate
// native dynamic linker injection on Linux.
func getNativeDangerousPrefixes() []string {
	return []string{
		"LD_PRELOAD=",
		"LD_LIBRARY_PATH=",
		"LD_AUDIT=",
	}
}
