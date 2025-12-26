package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// ============================================================================
// Test Result Types
// ============================================================================

// SandboxTestResult captures the output of a sandboxed command.
type SandboxTestResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Error    error
}

// Succeeded returns true if the command exited with code 0.
func (r *SandboxTestResult) Succeeded() bool {
	return r.ExitCode == 0 && r.Error == nil
}

// Failed returns true if the command exited with a non-zero code.
func (r *SandboxTestResult) Failed() bool {
	return r.ExitCode != 0 || r.Error != nil
}

// ============================================================================
// Test Skip Helpers
// ============================================================================

// skipIfAlreadySandboxed skips the test if running inside a sandbox.
func skipIfAlreadySandboxed(t *testing.T) {
	t.Helper()
	if os.Getenv("FENCE_SANDBOX") == "1" {
		t.Skip("skipping: already running inside Fence sandbox")
	}
}

// skipIfCommandNotFound skips if a command is not available.
func skipIfCommandNotFound(t *testing.T, cmd string) {
	t.Helper()
	if _, err := exec.LookPath(cmd); err != nil {
		t.Skipf("skipping: command %q not found", cmd)
	}
}

// ============================================================================
// Test Assertions
// ============================================================================

// assertBlocked verifies that a command was blocked by the sandbox.
func assertBlocked(t *testing.T, result *SandboxTestResult) {
	t.Helper()
	if result.Succeeded() {
		t.Errorf("expected command to be blocked, but it succeeded\nstdout: %s\nstderr: %s",
			result.Stdout, result.Stderr)
	}
}

// assertAllowed verifies that a command was allowed and succeeded.
func assertAllowed(t *testing.T, result *SandboxTestResult) {
	t.Helper()
	if result.Failed() {
		t.Errorf("expected command to succeed, but it failed with exit code %d\nstdout: %s\nstderr: %s\nerror: %v",
			result.ExitCode, result.Stdout, result.Stderr, result.Error)
	}
}

// assertFileExists checks that a file exists.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file to exist: %s", path)
	}
}

// assertFileNotExists checks that a file does not exist.
func assertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file to not exist: %s", path)
	}
}

// assertContains checks that a string contains a substring.
func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q to contain %q", haystack, needle)
	}
}

// ============================================================================
// Test Configuration Helpers
// ============================================================================

// testConfig creates a test configuration with sensible defaults.
func testConfig() *config.Config {
	return &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{},
			DeniedDomains:  []string{},
		},
		Filesystem: config.FilesystemConfig{
			DenyRead:   []string{},
			AllowWrite: []string{},
			DenyWrite:  []string{},
		},
		Command: config.CommandConfig{
			Deny:        []string{},
			Allow:       []string{},
			UseDefaults: boolPtr(false), // Disable defaults for predictable testing
		},
	}
}

// testConfigWithWorkspace creates a config that allows writing to a workspace.
func testConfigWithWorkspace(workspacePath string) *config.Config {
	cfg := testConfig()
	cfg.Filesystem.AllowWrite = []string{workspacePath}
	return cfg
}

// testConfigWithNetwork creates a config that allows specific domains.
func testConfigWithNetwork(domains ...string) *config.Config {
	cfg := testConfig()
	cfg.Network.AllowedDomains = domains
	return cfg
}

// ============================================================================
// Sandbox Execution Helpers
// ============================================================================

// runUnderSandbox executes a command under the fence sandbox.
// This uses the sandbox Manager directly for integration testing.
func runUnderSandbox(t *testing.T, cfg *config.Config, command string, workDir string) *SandboxTestResult {
	t.Helper()
	skipIfAlreadySandboxed(t)

	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return &SandboxTestResult{Error: err}
		}
	}

	manager := NewManager(cfg, false, false)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return &SandboxTestResult{Error: err}
	}

	wrappedCmd, err := manager.WrapCommand(command)
	if err != nil {
		// Command was blocked before execution
		return &SandboxTestResult{
			ExitCode: 1,
			Stderr:   err.Error(),
			Error:    err,
		}
	}

	return executeShellCommand(t, wrappedCmd, workDir)
}

// runUnderSandboxWithTimeout runs a command with a timeout.
func runUnderSandboxWithTimeout(t *testing.T, cfg *config.Config, command string, workDir string, timeout time.Duration) *SandboxTestResult {
	t.Helper()
	skipIfAlreadySandboxed(t)

	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return &SandboxTestResult{Error: err}
		}
	}

	manager := NewManager(cfg, false, false)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return &SandboxTestResult{Error: err}
	}

	wrappedCmd, err := manager.WrapCommand(command)
	if err != nil {
		return &SandboxTestResult{
			ExitCode: 1,
			Stderr:   err.Error(),
			Error:    err,
		}
	}

	return executeShellCommandWithTimeout(t, wrappedCmd, workDir, timeout)
}

// executeShellCommand runs a command string via /bin/sh.
func executeShellCommand(t *testing.T, command string, workDir string) *SandboxTestResult {
	t.Helper()
	return executeShellCommandWithTimeout(t, command, workDir, 30*time.Second)
}

// executeShellCommandWithTimeout runs a command with a timeout.
func executeShellCommandWithTimeout(t *testing.T, command string, workDir string, timeout time.Duration) *SandboxTestResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	shell := "/bin/sh"
	if runtime.GOOS == "darwin" {
		shell = "/bin/bash"
	}

	cmd := exec.CommandContext(ctx, shell, "-c", command)
	cmd.Dir = workDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &SandboxTestResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.Error = ctx.Err()
		result.ExitCode = -1
		return result
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err
			result.ExitCode = -1
		}
	}

	return result
}

// ============================================================================
// Workspace Helpers
// ============================================================================

// createTempWorkspace creates a temporary directory for testing.
func createTempWorkspace(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fence-test-*")
	if err != nil {
		t.Fatalf("failed to create temp workspace: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// createTestFile creates a file in the workspace with the given content.
func createTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	return path
}

// createGitRepo creates a minimal git repository structure.
func createGitRepo(t *testing.T, dir string) string {
	t.Helper()
	gitDir := filepath.Join(dir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("failed to create .git/hooks: %v", err)
	}
	// Create a minimal config file
	createTestFile(t, gitDir, "config", "[core]\n\trepositoryformatversion = 0\n")
	return dir
}

// ============================================================================
// Common Integration Tests (run on all platforms)
// ============================================================================

func TestIntegration_BasicReadAllowed(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, "test.txt", "hello world")

	cfg := testConfigWithWorkspace(workspace)
	result := runUnderSandbox(t, cfg, "cat test.txt", workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello world")
}

func TestIntegration_EchoWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'hello from sandbox'", workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello from sandbox")
}

func TestIntegration_CommandDenyList(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"rm -rf"}

	result := runUnderSandbox(t, cfg, "rm -rf /tmp/should-not-run", workspace)

	assertBlocked(t, result)
	assertContains(t, result.Stderr, "blocked")
}

func TestIntegration_CommandAllowOverridesDeny(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"git push"}
	cfg.Command.Allow = []string{"git push origin docs"}

	// This should be blocked
	result := runUnderSandbox(t, cfg, "git push origin main", workspace)
	assertBlocked(t, result)

	// This should be allowed (by the allow override)
	// Note: it may still fail because git isn't configured, but it shouldn't be blocked
	result2 := runUnderSandbox(t, cfg, "git push origin docs", workspace)
	// We just check it wasn't blocked by command policy
	if result2.Error != nil {
		errStr := result2.Error.Error()
		if strings.Contains(errStr, "blocked") {
			t.Errorf("command should not have been blocked by policy")
		}
	}
}

func TestIntegration_ChainedCommandDeny(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"rm -rf"}

	// Chained command should be blocked
	result := runUnderSandbox(t, cfg, "ls && rm -rf /tmp/test", workspace)
	assertBlocked(t, result)
}

func TestIntegration_NestedShellCommandDeny(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"rm -rf"}

	// Nested shell invocation should be blocked
	result := runUnderSandbox(t, cfg, `bash -c "rm -rf /tmp/test"`, workspace)
	assertBlocked(t, result)
}

// ============================================================================
// Compatibility Tests
// ============================================================================

func TestIntegration_PythonWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, `python3 -c "print('hello from python')"`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello from python")
}

func TestIntegration_NodeWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "node")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, `node -e "console.log('hello from node')"`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "hello from node")
}

func TestIntegration_GitStatusWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "git")

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)

	// git status should work (read operation)
	result := runUnderSandbox(t, cfg, "git status", workspace)

	// May fail due to git config, but shouldn't crash
	// The important thing is it runs, not that it succeeds perfectly
	if result.Error != nil && strings.Contains(result.Error.Error(), "blocked") {
		t.Errorf("git status should not be blocked")
	}
}

func TestIntegration_LsWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	createTestFile(t, workspace, "file1.txt", "content1")
	createTestFile(t, workspace, "file2.txt", "content2")
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "ls", workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "file1.txt")
	assertContains(t, result.Stdout, "file2.txt")
}

func TestIntegration_PwdWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "pwd", workspace)

	assertAllowed(t, result)
	// Output should contain the workspace path (or its resolved symlink)
	if !strings.Contains(result.Stdout, filepath.Base(workspace)) &&
		result.Stdout == "" {
		t.Errorf("pwd should output the current directory")
	}
}

func TestIntegration_EnvWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "env | grep FENCE", workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "FENCE_SANDBOX=1")
}
