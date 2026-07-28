//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	if handled, exitCode, err := DispatchInternalHelper(os.Args); handled {
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(exitCode)
	}
	os.Exit(m.Run())
}

func testLinuxHelperPath(t testing.TB) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("locate Linux test helper: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve Linux test helper: %v", err)
	}
	return resolved
}

func configureIntegrationManager(t testing.TB, manager *Manager) {
	t.Helper()
	if err := manager.SetLinuxHelperPath(testLinuxHelperPath(t)); err != nil {
		t.Fatalf("configure Linux test helper: %v", err)
	}
}
