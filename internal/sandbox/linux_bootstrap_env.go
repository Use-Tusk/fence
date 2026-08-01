//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

type linuxBootstrapRuntimeEnvResult struct {
	cleanupPaths []string
}

func (result linuxBootstrapRuntimeEnvResult) Cleanup() {
	cleanupLinuxBootstrapPaths(result.cleanupPaths)
}

func applyLinuxBootstrapRuntimeEnv(plan linuxBootstrapRuntimeEnvPlan, tempRoot string) (linuxBootstrapRuntimeEnvResult, error) {
	result := linuxBootstrapRuntimeEnvResult{}
	keys := make([]string, 0, len(plan.Set))
	for key := range plan.Set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if err := os.Setenv(key, plan.Set[key]); err != nil {
			return result, fmt.Errorf("set Linux bootstrap environment variable %s: %w", key, err)
		}
	}

	if plan.RepairTMPDIR && !linuxBootstrapDirIsUsable(os.Getenv("TMPDIR")) {
		if !linuxBootstrapDirIsUsable(tempRoot) {
			return result, fmt.Errorf("Linux bootstrap temporary root %q is not usable", tempRoot)
		}
		if err := os.Setenv("TMPDIR", tempRoot); err != nil {
			return result, fmt.Errorf("set Linux bootstrap TMPDIR: %w", err)
		}
	}

	if plan.RepairXDGRuntimeDir && !linuxBootstrapDirIsUsable(os.Getenv("XDG_RUNTIME_DIR")) {
		runtimeDir, err := os.MkdirTemp(tempRoot, fmt.Sprintf("fence-runtime-%d-", os.Getuid()))
		if err != nil {
			if unsetErr := os.Unsetenv("XDG_RUNTIME_DIR"); unsetErr != nil {
				return result, fmt.Errorf(
					"create Linux bootstrap runtime directory: %v; unset XDG_RUNTIME_DIR: %w",
					err,
					unsetErr,
				)
			}
			return result, nil
		}
		// #nosec G302 -- XDG runtime directories must be private but traversable by their owner.
		if err := os.Chmod(runtimeDir, 0o700); err != nil {
			_ = os.RemoveAll(runtimeDir)
			return result, fmt.Errorf("set Linux bootstrap runtime directory permissions: %w", err)
		}
		if !linuxBootstrapDirIsUsable(runtimeDir) {
			_ = os.RemoveAll(runtimeDir)
			return result, fmt.Errorf("created Linux bootstrap runtime directory %q is not usable", runtimeDir)
		}
		if err := os.Setenv("XDG_RUNTIME_DIR", runtimeDir); err != nil {
			_ = os.RemoveAll(runtimeDir)
			return result, fmt.Errorf("set Linux bootstrap XDG_RUNTIME_DIR: %w", err)
		}
		result.cleanupPaths = append(result.cleanupPaths, runtimeDir)
	}

	return result, nil
}

func linuxBootstrapDirIsUsable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path) // #nosec G703 -- probing the inherited runtime directory is the purpose of this helper
	if err != nil || !info.IsDir() {
		return false
	}

	probe := filepath.Join(path, fmt.Sprintf(".fence-write-test-%d", os.Getpid()))
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304,G703 -- probe is intentionally created beneath the directory being tested
	if err != nil {
		return false
	}
	closeErr := file.Close()
	removeErr := os.Remove(probe) // #nosec G703 -- removes only the exact probe path created above
	return closeErr == nil && removeErr == nil
}
