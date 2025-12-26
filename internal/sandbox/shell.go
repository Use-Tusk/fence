// Package sandbox provides sandboxing functionality for macOS and Linux.
package sandbox

import (
	"fmt"
	"strings"
)

// ShellQuote quotes a slice of strings for shell execution.
func ShellQuote(args []string) string {
	var quoted []string
	for _, arg := range args {
		if needsQuoting(arg) {
			quoted = append(quoted, fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''")))
		} else {
			quoted = append(quoted, arg)
		}
	}
	return strings.Join(quoted, " ")
}

// ShellQuoteSingle quotes a single string for shell execution.
func ShellQuoteSingle(s string) string {
	if needsQuoting(s) {
		return fmt.Sprintf("'%s'", strings.ReplaceAll(s, "'", "'\\''"))
	}
	return s
}

// needsQuoting returns true if a string contains shell metacharacters.
func needsQuoting(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\'' ||
			c == '\\' || c == '$' || c == '`' || c == '!' || c == '*' ||
			c == '?' || c == '[' || c == ']' || c == '(' || c == ')' ||
			c == '{' || c == '}' || c == '<' || c == '>' || c == '|' ||
			c == '&' || c == ';' || c == '#' {
			return true
		}
	}
	return len(s) == 0
}
