//go:build darwin

package osutil

// getNativeDangerousPrefixes returns environment variable prefixes that indicate
// native dynamic linker injection on macOS.
func getNativeDangerousPrefixes() []string {
	return []string{
		"DYLD_INSERT_LIBRARIES=",
		"DYLD_LIBRARY_PATH=",
		"DYLD_FRAMEWORK_PATH=",
		"DYLD_FALLBACK_LIBRARY_PATH=",
		"DYLD_FALLBACK_FRAMEWORK_PATH=",
		"DYLD_VERSIONED_LIBRARY_PATH=",
		"DYLD_VERSIONED_FRAMEWORK_PATH=",
		"DYLD_FORCE_FLAT_NAMESPACE=",
		"DYLD_IMAGE_SUFFIX=",
		"DYLD_ROOT_PATH=",
	}
}
