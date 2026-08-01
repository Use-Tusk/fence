package sandbox

import (
	"strings"
	"testing"
)

func TestDispatchInternalHelperIgnoresNormalArguments(t *testing.T) {
	handled, exitCode, err := DispatchInternalHelper([]string{"app", "--verbose"})
	if handled || exitCode != 0 || err != nil {
		t.Fatalf("DispatchInternalHelper() = (%v, %d, %v), want unhandled", handled, exitCode, err)
	}
}

func TestDispatchInternalHelperValidatesLandlockCommand(t *testing.T) {
	handled, exitCode, err := DispatchInternalHelper([]string{"app", "--landlock-apply"})
	if !handled {
		t.Fatal("DispatchInternalHelper() did not handle Landlock mode")
	}
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if err == nil || !strings.Contains(err.Error(), "no command specified") {
		t.Fatalf("error = %v, want missing command", err)
	}
}

func TestParseLandlockWrapperArgs(t *testing.T) {
	debug, command, err := parseLandlockWrapperArgs([]string{
		"--debug",
		"--",
		"/bin/sh",
		"-c",
		"true",
	})
	if err != nil {
		t.Fatalf("parseLandlockWrapperArgs() error = %v", err)
	}
	if !debug {
		t.Fatal("debug = false, want true")
	}
	want := []string{"/bin/sh", "-c", "true"}
	if len(command) != len(want) {
		t.Fatalf("command = %#v, want %#v", command, want)
	}
	for i := range want {
		if command[i] != want[i] {
			t.Fatalf("command[%d] = %q, want %q", i, command[i], want[i])
		}
	}
}
