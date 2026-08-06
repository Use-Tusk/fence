package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fencesandbox/fence/internal/sandbox"
	"github.com/fencesandbox/fence/internal/toolcall"
)

const fenceSandboxEnvVar = "FENCE_SANDBOX"

const untrustedFenceCommandReason = "nested Fence command does not use the active hook policy"

type hookFenceOptions struct {
	SettingsPath string
	TemplateName string
	// AllowWrap opts into rewriting allowed shell commands to fence -c.
	// Currently only meaningful for Codex hooks (intent-only by default).
	AllowWrap bool
}

type shellHookRequest struct {
	Command   string
	CWD       string
	ToolInput map[string]any
}

type shellHookResult struct {
	Decision     hookShellDecision
	Reason       string
	UpdatedInput map[string]any
}

type hookShellDecision int

const (
	hookShellNoChange hookShellDecision = iota
	hookShellDeny
	hookShellWrap
)

func (o hookFenceOptions) normalized() (hookFenceOptions, error) {
	if o.SettingsPath == "" {
		return o, nil
	}

	resolvedPath, err := resolveCLIPath(o.SettingsPath, "")
	if err != nil {
		return hookFenceOptions{}, err
	}

	o.SettingsPath = resolvedPath
	return o, nil
}

func (o hookFenceOptions) fenceArgs() []string {
	args := make([]string, 0, 4)
	if o.SettingsPath != "" {
		args = append(args, "--settings", o.SettingsPath)
	}
	if o.TemplateName != "" {
		args = append(args, "--template", o.TemplateName)
	}
	return args
}

func resolveFenceExecutable() string {
	fenceExePath, err := os.Executable()
	if err != nil || fenceExePath == "" {
		return "fence"
	}
	return filepath.Clean(fenceExePath)
}

func wrapShellCommand(command, fenceExePath string, extraFenceArgs []string) string {
	args := make([]string, 0, len(extraFenceArgs)+3)
	args = append(args, fenceExePath)
	args = append(args, extraFenceArgs...)
	args = append(args, "-c", command)
	return sandbox.ShellQuote(args)
}

func evaluateShellHookRequest(request shellHookRequest, fenceExePath string, extraFenceArgs []string) (shellHookResult, bool, error) {
	trimmed := strings.TrimSpace(request.Command)
	if trimmed == "" {
		return shellHookResult{}, false, nil
	}

	blocked, err := isHookCommandBlocked(request.Command, request.CWD, extraFenceArgs)
	if err != nil {
		return shellHookResult{}, false, err
	}
	if blocked {
		return shellHookResult{Decision: hookShellDeny}, true, nil
	}

	if isPureCDCommand(trimmed) || isTrustedFencedCommand(trimmed, fenceExePath, extraFenceArgs) {
		return shellHookResult{}, false, nil
	}
	if isAlreadyFencedCommand(trimmed, fenceExePath) {
		return shellHookResult{
			Decision: hookShellDeny,
			Reason:   untrustedFenceCommandReason,
		}, true, nil
	}

	if os.Getenv(fenceSandboxEnvVar) == "1" {
		return shellHookResult{}, false, nil
	}

	updatedInput := cloneJSONMap(request.ToolInput)
	updatedInput["command"] = wrapShellCommand(request.Command, fenceExePath, extraFenceArgs)
	return shellHookResult{
		Decision:     hookShellWrap,
		UpdatedInput: updatedInput,
	}, true, nil
}

func buildCompatiblePreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	payload, err := io.ReadAll(stdin)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read hook JSON: %w", err)
	}

	response, changed, err := buildClaudePreToolUseResponse(bytes.NewReader(payload), fenceExePath, extraFenceArgs)
	if err != nil {
		return nil, false, err
	}
	if changed {
		return response, true, nil
	}

	return buildCursorPreToolUseResponse(bytes.NewReader(payload), fenceExePath, extraFenceArgs)
}

func isHookCommandBlocked(command, commandCWD string, extraFenceArgs []string) (bool, error) {
	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return false, err
	}

	activeConfig, err := loadActiveConfigAudit(commandCWD, hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return false, err
	}

	return sandbox.CheckCommand(command, activeConfig.Config) != nil, nil
}

func extractHookCommandCWD(toolInput map[string]any, fallback string) string {
	if cwd, ok := stringFromJSONMap(toolInput, "cwd"); ok {
		return cwd
	}
	if cwd, ok := stringFromJSONMap(toolInput, "working_directory"); ok {
		return cwd
	}
	if cwd, ok := stringFromJSONMap(toolInput, "workingDirectory"); ok {
		return cwd
	}
	return fallback
}

func stringFromJSONMap(input map[string]any, key string) (string, bool) {
	if input == nil {
		return "", false
	}
	value, ok := input[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok && text != ""
}

func parseHookFenceOptionsArgs(args []string) (hookFenceOptions, error) {
	var hookOptions hookFenceOptions

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--settings" || arg == "-s":
			if i+1 >= len(args) {
				return hookFenceOptions{}, fmt.Errorf("missing value for %s", arg)
			}
			hookOptions.SettingsPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--settings="):
			hookOptions.SettingsPath = strings.TrimPrefix(arg, "--settings=")
		case arg == "--template" || arg == "-t":
			if i+1 >= len(args) {
				return hookFenceOptions{}, fmt.Errorf("missing value for %s", arg)
			}
			hookOptions.TemplateName = args[i+1]
			i++
		case strings.HasPrefix(arg, "--template="):
			hookOptions.TemplateName = strings.TrimPrefix(arg, "--template=")
		case arg == "--wrap":
			hookOptions.AllowWrap = true
		default:
			return hookFenceOptions{}, fmt.Errorf("unknown hook helper flag: %s", arg)
		}
	}

	if hookOptions.SettingsPath != "" && hookOptions.TemplateName != "" {
		return hookFenceOptions{}, fmt.Errorf("cannot use --settings and --template together")
	}

	return hookOptions.normalized()
}

func isPureCDCommand(command string) bool {
	if command != "cd" && !strings.HasPrefix(command, "cd ") && !strings.HasPrefix(command, "cd\t") {
		return false
	}
	if containsCommandSubstitution(command) {
		return false
	}

	for _, separator := range []string{"&&", "||", ";", "|", ">", "<", "\n", "\r"} {
		if strings.Contains(command, separator) {
			return false
		}
	}

	return true
}

func containsCommandSubstitution(command string) bool {
	var inSingleQuote bool
	var inDoubleQuote bool
	var escaped bool

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if inSingleQuote {
			continue
		}
		if c == '`' {
			return true
		}
		if c == '$' && i+1 < len(runes) && runes[i+1] == '(' {
			if i+2 < len(runes) && runes[i+2] == '(' {
				continue
			}
			return true
		}
	}

	return false
}

func isAlreadyFencedCommand(command, fenceExePath string) bool {
	quotedFenceExePath := sandbox.ShellQuote([]string{fenceExePath})
	executables := []string{
		"fence",
		fenceExePath,
		quotedFenceExePath,
	}
	for _, executable := range executables {
		if hasShellWordPrefix(command, executable) {
			return true
		}
	}

	args, ok := parseCanonicalShellArgs(strings.ReplaceAll(command, "\t", " "))
	if !ok {
		return false
	}
	args = stripLiteralFenceLaunchers(args)
	return len(args) > 0 && (args[0] == "fence" || args[0] == fenceExePath)
}

func hasShellWordPrefix(command, word string) bool {
	if command == word {
		return true
	}
	if !strings.HasPrefix(command, word) || len(command) == len(word) {
		return false
	}
	next := command[len(word)]
	return next == ' ' || next == '\t'
}

// stripLiteralFenceLaunchers handles common direct shell spellings
// without being a complete shell interpreter. Intent-only hooks remain
// best-effort against dynamic or indirect command construction.
func stripLiteralFenceLaunchers(args []string) []string {
	for len(args) > 0 {
		switch args[0] {
		case "command":
			args = args[1:]
			for len(args) > 0 && (args[0] == "-p" || args[0] == "--") {
				args = args[1:]
			}
		case "env":
			args = args[1:]
			for len(args) > 0 {
				switch {
				case args[0] == "--" || args[0] == "-i" || args[0] == "--ignore-environment":
					args = args[1:]
				case envOptionConsumesNextArg(args[0]):
					if len(args) < 2 {
						return nil
					}
					args = args[2:]
				case isInlineEnvOption(args[0]):
					args = args[1:]
				case !strings.HasPrefix(args[0], "-") && strings.Contains(args[0], "="):
					args = args[1:]
				default:
					return args
				}
			}
		default:
			return args
		}
	}
	return args
}

func envOptionConsumesNextArg(arg string) bool {
	return arg == "-u" || arg == "--unset" || arg == "-C" || arg == "--chdir"
}

func isInlineEnvOption(arg string) bool {
	return (strings.HasPrefix(arg, "-u") && len(arg) > len("-u")) ||
		(strings.HasPrefix(arg, "-C") && len(arg) > len("-C")) ||
		strings.HasPrefix(arg, "--unset=") ||
		strings.HasPrefix(arg, "--chdir=")
}

func denyUntrustedFenceCommand(decision toolcall.Decision, fenceExePath string) toolcall.Decision {
	if decision.Outcome != toolcall.OutcomeAllow || decision.Domain != toolcall.DomainCommand {
		return decision
	}
	if !isAlreadyFencedCommand(strings.TrimSpace(decision.Value), fenceExePath) {
		return decision
	}

	decision.Outcome = toolcall.OutcomeDeny
	decision.Reason = untrustedFenceCommandReason
	return decision
}

func isTrustedFencedCommand(command, fenceExePath string, extraFenceArgs []string) bool {
	args, ok := parseCanonicalShellArgs(command)
	if !ok || len(args) != len(extraFenceArgs)+3 {
		return false
	}
	if args[0] != fenceExePath {
		return false
	}
	for i, arg := range extraFenceArgs {
		if args[i+1] != arg {
			return false
		}
	}
	return args[len(args)-2] == "-c"
}

// parseCanonicalShellArgs accepts only the literal shell syntax emitted by
// sandbox.ShellQuote. Re-quoting the parsed argv rejects alternate spellings,
// expansions, operators, and trailing shell commands.
func parseCanonicalShellArgs(command string) ([]string, bool) {
	var args []string
	var current strings.Builder
	var inSingleQuote bool
	var escaped bool
	var wordStarted bool

	for _, c := range command {
		switch {
		case escaped:
			current.WriteRune(c)
			escaped = false
			wordStarted = true
		case c == '\\' && !inSingleQuote:
			escaped = true
			wordStarted = true
		case c == '\'':
			inSingleQuote = !inSingleQuote
			wordStarted = true
		case c == ' ' && !inSingleQuote:
			if !wordStarted {
				return nil, false
			}
			args = append(args, current.String())
			current.Reset()
			wordStarted = false
		default:
			current.WriteRune(c)
			wordStarted = true
		}
	}

	if escaped || inSingleQuote || !wordStarted {
		return nil, false
	}
	args = append(args, current.String())
	return args, sandbox.ShellQuote(args) == command
}

func cloneJSONMap(input map[string]any) map[string]any {
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
