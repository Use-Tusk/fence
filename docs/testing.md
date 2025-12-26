# Testing

We maintain a test suite covering unit tests, integration tests, and smoke tests.

## Quick Start

```bash
# Run all tests
make test

# Run unit tests
go test ./...

# Run integration tests
go test -v -run 'TestIntegration|TestLinux|TestMacOS' ./internal/sandbox/...

# Run smoke tests (end-to-end)
./scripts/smoke_test.sh
```

## Test Types

### Unit Tests

To verify individual functions and logic in isolation.

**Run:**

```bash
go test ./internal/...
```

### Integration Tests

Integration tests verify that the sandbox actually restricts/allows operations as expected. They spawn real processes under the sandbox and check outcomes.

**Files:**

- [`internal/sandbox/integration_test.go`](/internal/sandbox/integration_test.go) - Cross-platform tests
- [`internal/sandbox/integration_linux_test.go`](/internal/sandbox/integration_linux_test.go) - Linux-specific (Landlock, seccomp, bwrap)
- [`internal/sandbox/integration_macos_test.go`](/internal/sandbox/integration_macos_test.go) - macOS-specific (Seatbelt)

**What they test:**

- Filesystem restrictions (read/write blocking)
- Network blocking and proxy integration
- Command blocking
- Developer tool compatibility (Python, Node, Git)
- Security scenarios (symlink escape, path traversal)
- Platform-specific features (seccomp syscall filtering, Seatbelt profiles)

**Run:**

```bash
# All integration tests (platform-appropriate tests run automatically)
go test -v -run 'TestIntegration|TestLinux|TestMacOS' ./internal/sandbox/...

# Linux-specific only
go test -v -run 'TestLinux' ./internal/sandbox/...

# macOS-specific only
go test -v -run 'TestMacOS' ./internal/sandbox/...

# With verbose output
go test -v -count=1 ./internal/sandbox/...
```

### Smoke Tests

Smoke tests verify the compiled `fence` binary works end-to-end. Unlike integration tests (which test internal Go APIs), smoke tests exercise the CLI interface.

**File:** [`scripts/smoke_test.sh`](/scripts/smoke_test.sh)

**What they test:**

- CLI flags (--version, -c, -s)
- Filesystem restrictions via settings file
- Command blocking via settings file
- Network blocking
- Environment variable injection (FENCE_SANDBOX, HTTP_PROXY)
- Tool compatibility (python3, node, git, rg) - ensure that frequently used tools don't break in sandbox

**Run:**

```bash
# Build and test
./scripts/smoke_test.sh

# Test specific binary
./scripts/smoke_test.sh ./path/to/fence

# Enable network tests (requires internet)
FENCE_TEST_NETWORK=1 ./scripts/smoke_test.sh
```

## Platform-Specific Behavior

### Linux

Linux tests verify:

- Landlock - Filesystem access control
- seccomp - Syscall filtering (blocks dangerous syscalls)
- bwrap - User namespace isolation
- Network namespaces - Network isolation via proxy

Requirements:

- Linux kernel 5.13+ (for Landlock)
- `bwrap` (bubblewrap) installed
- User namespace support enabled

### macOS

macOS tests verify:

- Seatbelt (sandbox-exec) - Built-in sandboxing
- Network proxy - All network traffic routed through proxy

Requirements:

- macOS 10.15+ (Catalina or later)
- No special setup needed (Seatbelt is built-in)

## Writing Tests

### Integration Test Helpers

The `integration_test.go` file provides helpers for writing sandbox tests:

```go
// Skip helpers
skipIfAlreadySandboxed(t)              // Skip if running inside Fence
skipIfCommandNotFound(t, "python3")    // Skip if command missing

// Run a command under the sandbox
result := runUnderSandbox(t, cfg, "touch /etc/test", workspace)

// Assertions
assertBlocked(t, result)      // Command should have failed
assertAllowed(t, result)      // Command should have succeeded
assertContains(t, result.Stdout, "expected")

// File assertions
assertFileExists(t, "/path/to/file")
assertFileNotExists(t, "/path/to/file")

// Config helpers
cfg := testConfig()                          // Basic deny-all config
cfg := testConfigWithWorkspace(workspace)    // Allow writes to workspace
cfg := testConfigWithNetwork("example.com")  // Allow domain
```

### Example Test

```go
func TestLinux_CustomFeature(t *testing.T) {
    skipIfAlreadySandboxed(t)
    
    workspace := createTempWorkspace(t)
    cfg := testConfigWithWorkspace(workspace)
    
    // Test that writes outside workspace are blocked
    result := runUnderSandbox(t, cfg, "touch /tmp/outside.txt", workspace)
    assertBlocked(t, result)
    assertFileNotExists(t, "/tmp/outside.txt")
    
    // Test that writes inside workspace work
    insideFile := filepath.Join(workspace, "inside.txt")
    result = runUnderSandbox(t, cfg, "touch "+insideFile, workspace)
    assertAllowed(t, result)
    assertFileExists(t, insideFile)
}
```

## CI

A [GitHub Actions workflow](/.github/workflows/main.yml) runs build, lint, and platform-specific tests.

Tests are designed to pass in CI environments (all dependencies installed) and local development machines (either Linux or MacOS).

If tests fail in CI, it indicates a real problem with the sandbox (not an environment limitation). The tests should fail loudly if:

- bwrap can't create user namespaces
- Landlock is not available
- Seatbelt fails to apply profiles
- Network isolation isn't working

## Test Coverage

Check test coverage with:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # View in browser
go tool cover -func=coverage.out  # Summary
```

## Debugging Test Failures

### View sandbox logs

```bash
# Run with verbose Go test output
go test -v -run TestSpecificTest ./internal/sandbox/...
```

### Run command manually

```bash
# Replicate what the test does
./fence -c "the-command-that-failed"

# With a settings file
./fence -s /path/to/settings.json -c "command"
```

### Check platform capabilities

```bash
# Linux: Check kernel features
cat /proc/sys/kernel/unprivileged_userns_clone  # Should be 1
uname -r  # Kernel version (need 5.13+ for Landlock)

# macOS: Check sandbox-exec
sandbox-exec -p '(version 1)(allow default)' /bin/echo "sandbox works"
```

## Test Naming Conventions

- `Test<Platform>_<Feature>` - Platform-specific tests (e.g., `TestLinux_LandlockBlocksWrite`)
- `TestIntegration_<Feature>` - Cross-platform tests (e.g., `TestIntegration_PythonWorks`)
- `Test<Function>` - Unit tests (e.g., `TestShouldBlockCommand`)
