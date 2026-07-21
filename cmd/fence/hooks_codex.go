package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fencesandbox/fence/internal/sandbox"
)

const codexPreToolUseMode = "--codex-pre-tool-use"

// codexWrapEnvVar opts into command rewriting without reinstalling the hook.
// Prefer installing with --wrap when you want wrap mode persistently.
const codexWrapEnvVar = "FENCE_CODEX_WRAP"

// codexPreToolUseEvent mirrors Codex's PreToolUse stdin envelope.
// See https://learn.chatgpt.com/docs/hooks
type codexPreToolUseEvent struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	CWD           string         `json:"cwd,omitempty"`
}

type codexPreToolUseResponse struct {
	HookSpecificOutput *codexPreToolUseHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type codexPreToolUseHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func runCodexPreToolUseMode() error {
	return runCodexPreToolUse(os.Stdin, os.Stdout, resolveFenceExecutable(), os.Args[2:])
}

func runCodexPreToolUse(stdin io.Reader, stdout io.Writer, fenceExePath string, extraFenceArgs []string) error {
	response, changed, err := buildCodexPreToolUseResponse(stdin, fenceExePath, extraFenceArgs)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	_, err = fmt.Fprintln(stdout, string(response))
	return err
}

func buildCodexPreToolUseResponse(stdin io.Reader, fenceExePath string, extraFenceArgs []string) ([]byte, bool, error) {
	var event codexPreToolUseEvent
	decoder := json.NewDecoder(stdin)
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, false, fmt.Errorf("failed to decode Codex hook JSON: %w", err)
	}

	if event.HookEventName != "" && event.HookEventName != "PreToolUse" {
		return nil, false, nil
	}
	// Bash only. apply_patch / Edit / Write put patch text in tool_input.command,
	// which is not a shell command Fence can enforce.
	if event.ToolName != "Bash" {
		return nil, false, nil
	}

	command, ok := event.ToolInput["command"].(string)
	if !ok {
		return nil, false, fmt.Errorf("%s tool_input.command missing or not a string", event.ToolName)
	}

	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return nil, false, err
	}
	// Nested fence -c must not see --wrap (helper-only flag).
	wrapArgs := hookOptions.fenceArgs()
	cwd := extractHookCommandCWD(event.ToolInput, event.CWD)

	if !codexAllowWrap(hookOptions) {
		return buildCodexIntentOnlyResponse(command, cwd, wrapArgs)
	}

	result, changed, err := evaluateShellHookRequest(shellHookRequest{
		Command:   command,
		CWD:       cwd,
		ToolInput: event.ToolInput,
	}, fenceExePath, wrapArgs)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return nil, false, nil
	}

	response := codexPreToolUseResponse{HookSpecificOutput: &codexPreToolUseHookSpecificOutput{
		HookEventName: "PreToolUse",
	}}
	switch result.Decision {
	case hookShellDeny:
		response.HookSpecificOutput.PermissionDecision = "deny"
		response.HookSpecificOutput.PermissionDecisionReason = codexDenyReason(command, wrapArgs)
	case hookShellWrap:
		response.HookSpecificOutput.PermissionDecision = "allow"
		response.HookSpecificOutput.UpdatedInput = result.UpdatedInput
	default:
		return nil, false, nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Codex hook response: %w", err)
	}
	return data, true, nil
}

// buildCodexIntentOnlyResponse denies blocked commands and otherwise leaves
// the tool call unchanged. This is the default for Codex because tool
// execution usually runs inside Codex's own sandbox, where nested fence -c
// cannot bind its HTTP proxy.
func buildCodexIntentOnlyResponse(command, cwd string, wrapArgs []string) ([]byte, bool, error) {
	if shouldSkipShellWrap(command, resolveFenceExecutable()) {
		return nil, false, nil
	}

	blocked, err := isHookCommandBlocked(command, cwd, wrapArgs)
	if err != nil {
		return nil, false, err
	}
	if !blocked {
		return nil, false, nil
	}

	response := codexPreToolUseResponse{HookSpecificOutput: &codexPreToolUseHookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: codexDenyReason(command, wrapArgs),
	}}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Codex hook response: %w", err)
	}
	return data, true, nil
}

func codexAllowWrap(hookOptions hookFenceOptions) bool {
	if hookOptions.AllowWrap {
		return true
	}
	return os.Getenv(codexWrapEnvVar) == "1"
}

func codexDenyReason(command string, extraFenceArgs []string) string {
	fallback := fmt.Sprintf("command blocked by Fence policy: %s", command)
	hookOptions, err := parseHookFenceOptionsArgs(extraFenceArgs)
	if err != nil {
		return fallback
	}
	activeConfig, err := loadActiveConfigAudit("", hookOptions.SettingsPath, hookOptions.TemplateName)
	if err != nil {
		return fallback
	}
	if checkErr := sandbox.CheckCommand(command, activeConfig.Config); checkErr != nil {
		return checkErr.Error()
	}
	return fallback
}
