//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyLinuxBootstrapRuntimeEnvSetsValuesAndRepairsTmpDir(t *testing.T) {
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(tempRoot, "missing"))

	result, err := applyLinuxBootstrapRuntimeEnv(linuxBootstrapRuntimeEnvPlan{
		Set: map[string]string{
			"FENCE_SANDBOX": "1",
			"HTTP_PROXY":    "http://127.0.0.1:3128",
		},
		RepairTMPDIR: true,
	}, tempRoot)
	if err != nil {
		t.Fatalf("applyLinuxBootstrapRuntimeEnv() error = %v", err)
	}
	defer result.Cleanup()

	if got := os.Getenv("TMPDIR"); got != tempRoot {
		t.Fatalf("TMPDIR = %q, want %q", got, tempRoot)
	}
	if got := os.Getenv("FENCE_SANDBOX"); got != "1" {
		t.Fatalf("FENCE_SANDBOX = %q, want 1", got)
	}
	if got := os.Getenv("HTTP_PROXY"); got != "http://127.0.0.1:3128" {
		t.Fatalf("HTTP_PROXY = %q", got)
	}
}

func TestApplyLinuxBootstrapRuntimeEnvPreservesUsableRuntimeDir(t *testing.T) {
	tempRoot := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	result, err := applyLinuxBootstrapRuntimeEnv(linuxBootstrapRuntimeEnvPlan{
		RepairXDGRuntimeDir: true,
	}, tempRoot)
	if err != nil {
		t.Fatalf("applyLinuxBootstrapRuntimeEnv() error = %v", err)
	}
	result.Cleanup()

	if got := os.Getenv("XDG_RUNTIME_DIR"); got != runtimeDir {
		t.Fatalf("XDG_RUNTIME_DIR = %q, want preserved %q", got, runtimeDir)
	}
	if _, err := os.Stat(runtimeDir); err != nil {
		t.Fatalf("preserved runtime directory was removed: %v", err)
	}
}

func TestApplyLinuxBootstrapRuntimeEnvCreatesAndCleansRuntimeDir(t *testing.T) {
	tempRoot := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tempRoot, "missing"))

	result, err := applyLinuxBootstrapRuntimeEnv(linuxBootstrapRuntimeEnvPlan{
		RepairXDGRuntimeDir: true,
	}, tempRoot)
	if err != nil {
		t.Fatalf("applyLinuxBootstrapRuntimeEnv() error = %v", err)
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	info, err := os.Stat(runtimeDir) // #nosec G703 -- runtimeDir is produced by the function under test
	if err != nil {
		t.Fatalf("stat created runtime directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("runtime directory mode = %#o, want %#o", got, 0o700)
	}
	if !linuxBootstrapDirIsUsable(runtimeDir) {
		t.Fatalf("created runtime directory %q is not usable", runtimeDir)
	}

	result.Cleanup()
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) { // #nosec G703 -- runtimeDir is produced by the function under test
		t.Fatalf("runtime directory still exists after cleanup: %v", err)
	}
}

func TestApplyLinuxBootstrapRuntimeEnvUnsetsRuntimeDirWhenCreationFails(t *testing.T) {
	tempRoot := filepath.Join(t.TempDir(), "missing")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tempRoot, "also-missing"))

	result, err := applyLinuxBootstrapRuntimeEnv(linuxBootstrapRuntimeEnvPlan{
		RepairXDGRuntimeDir: true,
	}, tempRoot)
	if err != nil {
		t.Fatalf("applyLinuxBootstrapRuntimeEnv() error = %v", err)
	}
	result.Cleanup()

	if _, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok {
		t.Fatal("XDG_RUNTIME_DIR remained set after fallback creation failed")
	}
}

func TestApplyLinuxBootstrapRuntimeEnvRejectsUnusableTmpRoot(t *testing.T) {
	tempRoot := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", filepath.Join(tempRoot, "also-missing"))

	_, err := applyLinuxBootstrapRuntimeEnv(linuxBootstrapRuntimeEnvPlan{
		RepairTMPDIR: true,
	}, tempRoot)
	if err == nil {
		t.Fatal("applyLinuxBootstrapRuntimeEnv() succeeded with unusable temporary root")
	}
}
