package main

import "testing"

func TestContainsHelperMode(t *testing.T) {
	testCases := []struct {
		name       string
		command    string
		helperMode string
		want       bool
	}{
		{
			name:       "generated Claude hook",
			command:    "fence --claude-pre-tool-use",
			helperMode: claudePreToolUseMode,
			want:       true,
		},
		{
			name:       "generated Codex hook",
			command:    "fence --codex-pre-tool-use",
			helperMode: codexPreToolUseMode,
			want:       true,
		},
		{
			name:       "absolute fence path with settings",
			command:    `PATH=/tmp/bin /usr/local/bin/fence --claude-pre-tool-use --settings "/tmp/policy.json"`,
			helperMode: claudePreToolUseMode,
			want:       true,
		},
		{
			name:       "generated Cursor hook",
			command:    `"/Users/jy/bin/fence" "--cursor-pre-tool-use"`,
			helperMode: cursorPreToolUseMode,
			want:       true,
		},
		{
			name:       "unrelated command containing helper text",
			command:    "echo --claude-pre-tool-use",
			helperMode: claudePreToolUseMode,
			want:       false,
		},
		{
			name:       "similar but not exact flag",
			command:    "fence --claude-pre-tool-use-suffix",
			helperMode: claudePreToolUseMode,
			want:       false,
		},
		{
			name:       "different executable",
			command:    "other-fence --cursor-pre-tool-use",
			helperMode: cursorPreToolUseMode,
			want:       false,
		},
		{
			name:       "codex mode does not match claude",
			command:    "fence --codex-pre-tool-use",
			helperMode: claudePreToolUseMode,
			want:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsHelperMode(tc.command, tc.helperMode); got != tc.want {
				t.Fatalf("expected %v, got %v for %q", tc.want, got, tc.command)
			}
		})
	}
}
