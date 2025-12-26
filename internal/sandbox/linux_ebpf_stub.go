//go:build !linux

// Package sandbox provides sandboxing functionality for macOS and Linux.
package sandbox

import "time"

// EBPFMonitor is a stub for non-Linux platforms.
type EBPFMonitor struct{}

// NewEBPFMonitor creates a stub monitor.
func NewEBPFMonitor(pid int, debug bool) *EBPFMonitor {
	return &EBPFMonitor{}
}

// Start is a no-op on non-Linux platforms.
func (m *EBPFMonitor) Start() error { return nil }

// Stop is a no-op on non-Linux platforms.
func (m *EBPFMonitor) Stop() {}

// IsEBPFAvailable returns false on non-Linux platforms.
func IsEBPFAvailable() bool { return false }

// RequiredCapabilities returns empty on non-Linux platforms.
func RequiredCapabilities() []string { return nil }

// CheckBpftraceAvailable returns false on non-Linux platforms.
func CheckBpftraceAvailable() bool { return false }

// ViolationEvent is a stub for non-Linux platforms.
type ViolationEvent struct {
	Timestamp time.Time
	Type      string
	Operation string
	Path      string
	PID       int
	Comm      string
	Errno     int
}

// FormatViolation returns empty on non-Linux platforms.
func (v *ViolationEvent) FormatViolation() string { return "" }

// EnsureTracingSetup returns nil on non-Linux platforms.
func EnsureTracingSetup() error { return nil }
