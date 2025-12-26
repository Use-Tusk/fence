//go:build !linux

// Package sandbox provides sandboxing functionality for macOS and Linux.
package sandbox

// SeccompFilter is a stub for non-Linux platforms.
type SeccompFilter struct {
	debug bool
}

// NewSeccompFilter creates a stub seccomp filter.
func NewSeccompFilter(debug bool) *SeccompFilter {
	return &SeccompFilter{debug: debug}
}

// GenerateBPFFilter returns an error on non-Linux platforms.
func (s *SeccompFilter) GenerateBPFFilter() (string, error) {
	return "", nil
}

// CleanupFilter is a no-op on non-Linux platforms.
func (s *SeccompFilter) CleanupFilter(path string) {}

// DangerousSyscalls is empty on non-Linux platforms.
var DangerousSyscalls []string
