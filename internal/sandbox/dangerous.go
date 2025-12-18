// Package sandbox provides sandboxing functionality for macOS and Linux.
package sandbox

import (
	"os"
	"path/filepath"
)

// DangerousFiles lists files that should be protected from writes.
// These files can be used for code execution or data exfiltration.
var DangerousFiles = []string{
	".gitconfig",
	".gitmodules",
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",
	".ripgreprc",
	".mcp.json",
}

// DangerousDirectories lists directories that should be protected from writes.
// Excludes .git since we need it writable for git operations.
var DangerousDirectories = []string{
	".vscode",
	".idea",
	".claude/commands",
	".claude/agents",
}

// GetDefaultWritePaths returns system paths that should be writable for commands to work.
func GetDefaultWritePaths() []string {
	home, _ := os.UserHomeDir()

	paths := []string{
		"/dev/stdout",
		"/dev/stderr",
		"/dev/null",
		"/dev/tty",
		"/dev/dtracehelper",
		"/dev/autofs_nowait",
		"/tmp/fence",
		"/private/tmp/fence",
	}

	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".npm/_logs"),
			filepath.Join(home, ".fence/debug"),
		)
	}

	return paths
}

// GetMandatoryDenyPatterns returns glob patterns for paths that must always be protected.
func GetMandatoryDenyPatterns(cwd string, allowGitConfig bool) []string {
	var patterns []string

	// Dangerous files - in CWD and all subdirectories
	for _, f := range DangerousFiles {
		patterns = append(patterns, filepath.Join(cwd, f))
		patterns = append(patterns, "**/"+f)
	}

	// Dangerous directories
	for _, d := range DangerousDirectories {
		patterns = append(patterns, filepath.Join(cwd, d))
		patterns = append(patterns, "**/"+d+"/**")
	}

	// Git hooks are always blocked
	patterns = append(patterns, filepath.Join(cwd, ".git/hooks"))
	patterns = append(patterns, "**/.git/hooks/**")

	// Git config is conditionally blocked
	if !allowGitConfig {
		patterns = append(patterns, filepath.Join(cwd, ".git/config"))
		patterns = append(patterns, "**/.git/config")
	}

	return patterns
}
