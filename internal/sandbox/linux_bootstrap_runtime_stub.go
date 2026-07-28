//go:build !linux

package sandbox

import "fmt"

func RunLinuxBootstrapInitFromEnv() (int, error) {
	return 1, fmt.Errorf("Linux bootstrap initializer is only available on Linux")
}

func RunLinuxBootstrapBridgeFromEnv() (int, error) {
	return 1, fmt.Errorf("Linux bootstrap bridge helper is only available on Linux")
}
