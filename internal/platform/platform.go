// Package platform provides OS detection utilities.
package platform

import "runtime"

// Type represents the detected platform.
type Type string

const (
	MacOS   Type = "macos"
	Linux   Type = "linux"
	Windows Type = "windows"
	Unknown Type = "unknown"
)

// Detect returns the current platform type.
func Detect() Type {
	switch runtime.GOOS {
	case "darwin":
		return MacOS
	case "linux":
		return Linux
	case "windows":
		return Windows
	default:
		return Unknown
	}
}

// IsSupported returns true if the platform supports sandboxing.
func IsSupported() bool {
	p := Detect()
	return p == MacOS || p == Linux
}
