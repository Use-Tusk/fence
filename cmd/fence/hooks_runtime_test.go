package main

import "testing"

func TestIsPureCDCommand(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "plain cd",
			command: "cd ../repo",
			want:    true,
		},
		{
			name:    "environment expansion",
			command: `cd "$HOME/tmp"`,
			want:    true,
		},
		{
			name:    "single quoted literal substitution syntax",
			command: `cd '$(pwd)'`,
			want:    true,
		},
		{
			name:    "command substitution",
			command: "cd $(pwd)",
			want:    false,
		},
		{
			name:    "command substitution in double quotes",
			command: `cd "$(pwd)"`,
			want:    false,
		},
		{
			name:    "backtick substitution",
			command: "cd `pwd`",
			want:    false,
		},
		{
			name:    "arithmetic expansion",
			command: "cd $((1 + 1))",
			want:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPureCDCommand(tc.command); got != tc.want {
				t.Fatalf("expected %v, got %v for %q", tc.want, got, tc.command)
			}
		})
	}
}

func TestIsTrustedFencedCommand(t *testing.T) {
	fenceExePath := "/opt/Fence App/bin/fence"
	extraFenceArgs := []string{"--settings", "/tmp/pinned policy.json"}
	trusted := wrapShellCommand(`printf '%s\n' "hello world"`, fenceExePath, extraFenceArgs)

	testCases := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "canonical wrapper",
			command: trusted,
			want:    true,
		},
		{
			name:    "different settings",
			command: wrapShellCommand("npm test", fenceExePath, []string{"--settings", "/tmp/weaker.json"}),
			want:    false,
		},
		{
			name:    "bare fence from path",
			command: "fence --settings /tmp/weaker.json -c id",
			want:    false,
		},
		{
			name:    "trailing shell command",
			command: trusted + " && id",
			want:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTrustedFencedCommand(tc.command, fenceExePath, extraFenceArgs); got != tc.want {
				t.Fatalf("isTrustedFencedCommand() = %v, want %v for %q", got, tc.want, tc.command)
			}
		})
	}
}
