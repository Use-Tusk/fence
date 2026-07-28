//go:build linux

package sandbox

import (
	"os/exec"
	"testing"
	"time"
)

func TestWaitForLinuxBootstrapProcessExitUsesPidfd(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	done := make(chan struct{})
	go func() {
		waitForLinuxBootstrapProcessExit(cmd.Process.Pid)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("process-exit watcher returned while child was still running")
	case <-time.After(100 * time.Millisecond):
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("process-exit watcher did not return after child exited")
	}
}

func TestWithoutEnvironmentKeysRemovesOnlyRequestedKeys(t *testing.T) {
	got := withoutEnvironmentKeys(
		[]string{"KEEP=value", "DROP=secret", "EMPTY=", "MALFORMED"},
		"DROP",
	)
	want := []string{"KEEP=value", "EMPTY=", "MALFORMED"}
	if len(got) != len(want) {
		t.Fatalf("filtered environment = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filtered environment[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
