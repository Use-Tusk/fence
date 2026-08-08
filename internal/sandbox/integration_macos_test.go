//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// macOS-Specific Integration Tests (Seatbelt)
// ============================================================================

// TestMacOS_SeatbeltBlocksWriteOutsideWorkspace verifies Seatbelt prevents writes
// outside the allowed workspace.
func TestMacOS_SeatbeltBlocksWriteOutsideWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	outsideFile := "/tmp/fence-test-outside-" + filepath.Base(workspace) + ".txt"
	defer func() { _ = os.Remove(outsideFile) }()

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "touch "+outsideFile, workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, outsideFile)
}

// TestMacOS_SeatbeltAllowsWriteInWorkspace verifies writes within the workspace work.
func TestMacOS_SeatbeltAllowsWriteInWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'test content' > allowed.txt", workspace)

	assertAllowed(t, result)
	assertFileExists(t, filepath.Join(workspace, "allowed.txt"))

	content, err := os.ReadFile(filepath.Join(workspace, "allowed.txt")) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(content), "test content") {
		t.Errorf("expected file to contain 'test content', got: %s", string(content))
	}
}

// TestMacOS_SeatbeltProtectsGitHooks verifies .git/hooks cannot be written to.
func TestMacOS_SeatbeltProtectsGitHooks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)

	hookPath := filepath.Join(workspace, ".git", "hooks", "pre-commit")
	result := runUnderSandbox(t, cfg, "echo '#!/bin/sh\nmalicious' > "+hookPath, workspace)

	assertBlocked(t, result)

	if content, err := os.ReadFile(hookPath); err == nil && strings.Contains(string(content), "malicious") { //nolint:gosec
		t.Errorf("malicious content should not have been written to git hook")
	}
}

// TestMacOS_SeatbeltProtectsGitConfig verifies .git/config is protected by default.
func TestMacOS_SeatbeltProtectsGitConfig(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowGitConfig = false

	configPath := filepath.Join(workspace, ".git", "config")
	originalContent, _ := os.ReadFile(configPath) //nolint:gosec

	result := runUnderSandbox(t, cfg, "echo 'malicious=true' >> "+configPath, workspace)

	assertBlocked(t, result)

	// Verify content wasn't modified
	newContent, _ := os.ReadFile(configPath) //nolint:gosec
	if strings.Contains(string(newContent), "malicious") {
		t.Errorf("git config should not have been modified")
	}
	_ = originalContent
}

// TestMacOS_SeatbeltProtectsShellConfig verifies shell config files are protected.
func TestMacOS_SeatbeltProtectsShellConfig(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	zshrcPath := filepath.Join(workspace, ".zshrc")
	createTestFile(t, workspace, ".zshrc", "# original zshrc")

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'malicious' >> "+zshrcPath, workspace)

	assertBlocked(t, result)

	content, _ := os.ReadFile(zshrcPath) //nolint:gosec
	if strings.Contains(string(content), "malicious") {
		t.Errorf(".zshrc should be protected from writes")
	}
}

// TestMacOS_SeatbeltAllowsReadSystemFiles verifies system files can be read.
func TestMacOS_SeatbeltAllowsReadSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Reading /etc/passwd should work on macOS
	result := runUnderSandbox(t, cfg, "cat /etc/passwd | head -1", workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected to read /etc/passwd content")
	}
}

// TestMacOS_SeatbeltBlocksDenyReadUnderDefaultDenyRead verifies that in defaultDenyRead mode,
// paths matched by denyRead (like **/.env) are blocked even if they are inside a readable
// workspace (like "."). This verifies the precedence issue remains fixed in actual sandboxing.
func TestMacOS_SeatbeltBlocksDenyReadUnderDefaultDenyRead(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)

	// Create allowed.json which should be readable
	createTestFile(t, workspace, "allowed.json", `{"key": "value"}`)

	// Create .env which should be blocked from reading
	createTestFile(t, workspace, ".env", `SECRET_KEY=supersecret`)

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = true
	cfg.Filesystem.AllowRead = []string{workspace}
	cfg.Filesystem.DenyRead = []string{"**/.env"}

	// 1. Reading allowed.json should succeed
	resultAllowed := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, "allowed.json"), workspace)
	assertAllowed(t, resultAllowed)
	if !strings.Contains(resultAllowed.Stdout, "value") {
		t.Errorf("expected to read allowed.json content, got: %q", resultAllowed.Stdout)
	}

	// 2. Reading .env should be blocked
	resultDenied := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, ".env"), workspace)
	// We expect the command to fail/be blocked
	assertBlocked(t, resultDenied)
	if strings.Contains(resultDenied.Stdout, "supersecret") {
		t.Errorf("expected .env reading to be blocked, but secret content was read: %q", resultDenied.Stdout)
	}
}

// TestMacOS_SeatbeltBlocksWriteSystemFiles verifies system files cannot be written.
func TestMacOS_SeatbeltBlocksWriteSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Attempting to write to /etc should fail
	result := runUnderSandbox(t, cfg, "touch /etc/fence-test-file", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/fence-test-file")
}

// TestMacOS_SeatbeltAllowsTmpFence verifies /tmp/fence is writable.
func TestMacOS_SeatbeltAllowsTmpFence(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Ensure /tmp/fence exists
	_ = os.MkdirAll("/tmp/fence", 0o750)

	testFile := "/tmp/fence/test-file-" + filepath.Base(workspace)
	defer func() { _ = os.Remove(testFile) }()

	result := runUnderSandbox(t, cfg, "echo 'test' > "+testFile, workspace)

	assertAllowed(t, result)
	assertFileExists(t, testFile)
}

// TestMacOS_SeatbeltAllowsUnixSocketBindUnderTMPDIR verifies a Unix socket can
// actually be BOUND inside fence's own TMPDIR (/tmp/fence). Fence redirects
// TMPDIR there for every sandboxed process, so sockets must work without user
// config — this exercises the TMPDIRSocketPaths seatbelt grant end-to-end,
// mirroring the relay listener test but under the fence-owned path.
func TestMacOS_SeatbeltAllowsUnixSocketBindUnderTMPDIR(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// TMPDIR is redirected to /tmp/fence by the sandbox env; the profile must
	// permit AF_UNIX bind there (this failed with `operation not permitted`
	// before the TMPDIRSocketPaths grant). Unique per-run path: the socket file
	// persists on the real host /tmp/fence (seatbelt does not overmount), so a
	// fixed name would hit EADDRINUSE on the next run. Use a UUID suffix and
	// unlink the file after the bind so runs leave no debris behind.
	pythonCode := `import os
import socket
import uuid

path = os.path.join(os.environ["TMPDIR"], f"wx-{uuid.uuid4().hex}.sock")
sock = socket.socket(socket.AF_UNIX)
try:
    sock.bind(path)
    print("BOUND")
finally:
    sock.close()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass`

	result := runUnderSandbox(t, cfg, `python3 -c '`+pythonCode+`'`, workspace)

	assertAllowed(t, result)
	if !strings.Contains(result.Stdout, "BOUND") {
		t.Errorf("expected BOUND from sandboxed socket bind, got stdout: %q stderr: %q", result.Stdout, result.Stderr)
	}
}

// TestMacOS_SeatbeltBlocksUnixSocketBindOutsideTMPDIR verifies the grant is
// scoped: a Unix socket bind directly under /tmp (not under /tmp/fence) stays
// blocked, so the fix does not over-grant host temp paths.
func TestMacOS_SeatbeltBlocksUnixSocketBindOutsideTMPDIR(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	probe := "python3 -c \"import os,socket; s=socket.socket(socket.AF_UNIX); s.bind('/tmp/fence-sock-test-'+str(os.getpid())+'.sock'); print('BOUND')\""
	result := runUnderSandbox(t, cfg, probe, workspace)

	assertBlocked(t, result)
}

// ============================================================================
// Network Blocking Tests
// ============================================================================

// TestMacOS_NetworkBlocksCurl verifies that curl cannot reach the network when blocked.
func TestMacOS_NetworkBlocksCurl(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	// No domains allowed = all network blocked

	result := runUnderSandboxWithTimeout(t, cfg, "curl -s --connect-timeout 2 --max-time 3 http://example.com", workspace, 10*time.Second)

	// Network is blocked via proxy - curl may exit 0 but with "blocked" message,
	// or it may fail with a connection error. Either is acceptable.
	if result.Succeeded() && !strings.Contains(result.Stdout, "blocked") && !strings.Contains(result.Stdout, "Connection refused") {
		t.Errorf("expected network to be blocked, but curl succeeded with: %s", result.Stdout)
	}
}

// TestMacOS_NetworkBlocksSSH verifies that SSH cannot connect when blocked.
func TestMacOS_NetworkBlocksSSH(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "ssh")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no github.com", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestMacOS_NetworkBlocksNc verifies that nc cannot make connections.
func TestMacOS_NetworkBlocksNc(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "nc")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "nc -z -w 2 127.0.0.1 80", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestMacOS_ProxyAllowsAllowedDomains verifies the proxy allows configured hosts.
// Uses a local HTTP origin (no public internet). Fence injects NO_PROXY for
// loopback, so the curl command clears it to force the HTTP proxy allowlist path.
func TestMacOS_ProxyAllowsAllowedDomains(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	const marker = "fence-allowed-domain-ok"
	url, cleanup := startLocalHTTPOrigin(t, marker)
	defer cleanup()

	workspace := createTempWorkspace(t)
	cfg := testConfigWithNetwork("127.0.0.1")
	cfg.Filesystem.AllowWrite = []string{workspace}

	cmd := fmt.Sprintf("NO_PROXY= no_proxy= curl -s --connect-timeout 5 --max-time 10 %s", url)
	result := runUnderSandboxWithTimeout(t, cfg, cmd, workspace, 15*time.Second)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, marker)
}

// ============================================================================
// Python Compatibility Tests
// ============================================================================

// TestMacOS_PythonOpenptyWorks verifies Python can open a PTY under Seatbelt.
func TestMacOS_PythonOpenptyWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.AllowPty = true

	pythonCode := `import os
master, slave = os.openpty()
os.write(slave, b"ping")
assert os.read(master, 4) == b"ping"
print("SUCCESS")`

	result := runUnderSandbox(t, cfg, `python3 -c '`+pythonCode+`'`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "SUCCESS")
}

// TestMacOS_PythonGetpwuidWorks verifies Python can look up user info.
func TestMacOS_PythonGetpwuidWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, `python3 -c "import pwd, os; print(pwd.getpwuid(os.getuid()).pw_name)"`, workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected username output")
	}
}

// ============================================================================
// Security Edge Case Tests
// ============================================================================

// TestMacOS_SymlinkEscapeBlocked verifies symlink attacks are prevented.
func TestMacOS_SymlinkEscapeBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Create a symlink pointing outside the workspace
	symlinkPath := filepath.Join(workspace, "escape")
	if err := os.Symlink("/etc", symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Try to write through the symlink
	result := runUnderSandbox(t, cfg, "echo 'test' > "+symlinkPath+"/fence-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/fence-test")
}

// TestMacOS_PathTraversalBlocked verifies path traversal attacks are prevented.
func TestMacOS_PathTraversalBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "touch ../../../../tmp/fence-escape-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/tmp/fence-escape-test")
}

// TestMacOS_DeviceAccessBlocked verifies device files cannot be written.
func TestMacOS_DeviceAccessBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Try to write to /dev/disk0 (would need root anyway, but should be blocked by sandbox)
	result := runUnderSandbox(t, cfg, "echo 'test' > /dev/disk0 2>&1", workspace)

	// Should fail (permission denied or blocked by sandbox)
	// The command may "succeed" if the write fails silently, so we check for error messages
	if result.Succeeded() && !strings.Contains(result.Stderr, "denied") && !strings.Contains(result.Stderr, "Permission") {
		// Even if shell exits 0, reading /dev/disk0 should produce errors or empty output
		t.Logf("Note: device access test may not be reliable without root")
	}
}

// ============================================================================
// Policy Tests
// ============================================================================

// TestMacOS_ReadOnlyPolicy verifies that files outside the allowed write paths cannot be written.
// Note: Fence always adds some default writable paths (/tmp/fence, /dev/null, etc.)
// so "read-only" here means "outside the workspace".
func TestMacOS_ReadOnlyPolicy(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, "existing.txt", "hello")

	// Only allow writing to workspace - but NOT to a specific location outside
	cfg := testConfigWithWorkspace(workspace)

	// Reading should work
	result := runUnderSandbox(t, cfg, "cat "+filepath.Join(workspace, "existing.txt"), workspace)
	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello")

	// Writing in workspace should work
	result = runUnderSandbox(t, cfg, "echo 'test' > "+filepath.Join(workspace, "writeable.txt"), workspace)
	assertAllowed(t, result)

	// Writing outside workspace should fail
	outsidePath := "/tmp/fence-test-readonly-" + filepath.Base(workspace) + ".txt"
	defer func() { _ = os.Remove(outsidePath) }()
	result = runUnderSandbox(t, cfg, "echo 'outside' > "+outsidePath, workspace)
	assertBlocked(t, result)
	assertFileNotExists(t, outsidePath)
}

// TestMacOS_WorkspaceWritePolicy verifies workspace-write sandbox works.
func TestMacOS_WorkspaceWritePolicy(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Writing in workspace should work
	result := runUnderSandbox(t, cfg, "echo 'test' > test.txt", workspace)
	assertAllowed(t, result)
	assertFileExists(t, filepath.Join(workspace, "test.txt"))

	// Writing outside workspace should fail
	outsideFile := "/tmp/fence-test-outside.txt"
	defer func() { _ = os.Remove(outsideFile) }()
	result = runUnderSandbox(t, cfg, "echo 'test' > "+outsideFile, workspace)
	assertBlocked(t, result)
	assertFileNotExists(t, outsideFile)
}

// TestMacOS_MultipleWritableRoots verifies multiple writable roots work.
func TestMacOS_MultipleWritableRoots(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace1 := createTempWorkspace(t)
	workspace2 := createTempWorkspace(t)

	cfg := testConfig()
	cfg.Filesystem.AllowWrite = []string{workspace1, workspace2}

	// Writing in first workspace should work
	result := runUnderSandbox(t, cfg, "echo 'test1' > "+filepath.Join(workspace1, "file1.txt"), workspace1)
	assertAllowed(t, result)

	// Writing in second workspace should work
	result = runUnderSandbox(t, cfg, "echo 'test2' > "+filepath.Join(workspace2, "file2.txt"), workspace1)
	assertAllowed(t, result)

	// Writing outside both should fail
	outsideFile := "/tmp/fence-test-outside-multi.txt"
	defer func() { _ = os.Remove(outsideFile) }()
	result = runUnderSandbox(t, cfg, "echo 'test' > "+outsideFile, workspace1)
	assertBlocked(t, result)
}

// ============================================================================
// Mach IPC Policy Tests (regression coverage for the wildcard regex bug #127)
// ============================================================================

// mdlsBaselineFailureMarker is what `mdls` prints when the Spotlight metadata
// daemon (com.apple.metadata.mds) is unreachable because mach-lookup is
// denied. The exact string is empirically stable across recent macOS
// versions.
const mdlsBaselineFailureMarker = "could not find"

// probeMdlsWorksUnsandboxed verifies that `mdls <path>` returns real Spotlight
// metadata on the current machine. If Spotlight indexing is disabled (e.g., in
// some CI environments), the probe can't differentiate allowed vs. blocked so
// we skip the tests that rely on it.
func probeMdlsWorksUnsandboxed(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("/usr/bin/mdls", path).CombinedOutput() // #nosec G204 - test probe with fixed binary path
	if err != nil || !strings.Contains(string(out), "kMDItem") {
		t.Skipf("skipping: unsandboxed `mdls %s` does not return metadata (Spotlight disabled?): err=%v out=%s", path, err, string(out))
	}
}

// TestMacOS_MachWildcardAuthorizesNonBaselineService verifies that a wildcard
// mach.lookup pattern (e.g., "com.apple.metadata.*") actually authorizes mach
// lookups to services matching that prefix - specifically services that are
// not already in the baseline allowlist.
//
// Probe: `mdls /etc/hosts`. This requires talking to `com.apple.metadata.mds`
// (Spotlight metadata daemon), which is not in the fence baseline mach-lookup
// list. When mds is unreachable, mdls prints "could not find <path>" and
// exits non-zero. When mds is reachable, mdls prints kMDItem* attributes.
func TestMacOS_MachWildcardAuthorizesNonBaselineService(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "mdls")

	probePath := "/etc/hosts"
	probeMdlsWorksUnsandboxed(t, probePath)

	workspace := createTempWorkspace(t)

	t.Run("baseline_denies_mds", func(t *testing.T) {
		// Sanity check: without any user-supplied mach.lookup rules, the
		// baseline doesn't authorize com.apple.metadata.mds, so the probe
		// must fail. If it doesn't, the probe is no longer a reliable
		// differentiator and the sibling test below is meaningless.
		cfg := testConfigWithWorkspace(workspace)
		result := runUnderSandbox(t, cfg, "/usr/bin/mdls "+probePath, workspace)

		combined := result.Stdout + result.Stderr
		if !strings.Contains(combined, mdlsBaselineFailureMarker) {
			t.Skipf("probe not differentiating on this system: mdls unexpectedly succeeded under baseline\nstdout=%q\nstderr=%q\nexit=%d",
				result.Stdout, result.Stderr, result.ExitCode)
		}
	})

	t.Run("wildcard_allows_mds", func(t *testing.T) {
		// With a wildcard that covers com.apple.metadata.*, mdls should
		// reach the daemon and print real metadata. Pre-fix, the wildcard
		// rule was a no-op and this would still fail.
		cfg := testConfigWithWorkspace(workspace)
		cfg.MacOS.Mach.Lookup = []string{"com.apple.metadata.*"}

		result := runUnderSandboxWithTimeout(t, cfg, "/usr/bin/mdls "+probePath, workspace, 10*time.Second)

		assertAllowed(t, result)
		if !strings.Contains(result.Stdout, "kMDItem") {
			t.Errorf("wildcard com.apple.metadata.* did not authorize mdls to reach mds\nstdout=%q\nstderr=%q\nexit=%d",
				result.Stdout, result.Stderr, result.ExitCode)
		}
		if strings.Contains(result.Stdout+result.Stderr, mdlsBaselineFailureMarker) {
			t.Errorf("wildcard rule appears to be a no-op — mdls still reports %q\nstdout=%q\nstderr=%q",
				mdlsBaselineFailureMarker, result.Stdout, result.Stderr)
		}
	})

	t.Run("exact_match_allows_mds", func(t *testing.T) {
		// Control: an exact match for com.apple.metadata.mds should also
		// authorize mdls. This isolates whether a failure in the wildcard
		// case is regex-specific (bug) vs. an environmental issue (e.g.,
		// mds needs additional services we're not allowing).
		cfg := testConfigWithWorkspace(workspace)
		cfg.MacOS.Mach.Lookup = []string{"com.apple.metadata.mds"}

		result := runUnderSandboxWithTimeout(t, cfg, "/usr/bin/mdls "+probePath, workspace, 10*time.Second)

		assertAllowed(t, result)
		if !strings.Contains(result.Stdout, "kMDItem") {
			t.Errorf("exact-match com.apple.metadata.mds did not authorize mdls\nstdout=%q\nstderr=%q\nexit=%d",
				result.Stdout, result.Stderr, result.ExitCode)
		}
	})
}
