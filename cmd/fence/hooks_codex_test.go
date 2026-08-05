package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fencesandbox/fence/internal/sandbox"
)

func TestBuildCodexPreToolUseResponse_IntentOnlyAllowsUnblockedCommand(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test",
			"description": "Run tests"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected intent-only mode to leave unblocked commands unchanged")
	}
}

func TestBuildCodexPreToolUseResponse_IntentOnlyDeniesEnvFenceWithDifferentPolicy(t *testing.T) {
	t.Setenv(codexWrapEnvVar, "")

	settingsPath := filepath.Join(t.TempDir(), "strict.json")
	if err := os.WriteFile(settingsPath, []byte(`{
  "command": {
    "useDefaults": false
  }
}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "env -u FENCE_SANDBOX fence --settings /tmp/weaker.json -c 'npm test'"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected alternate-policy Fence command to be denied in intent-only mode")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if got := decoded.HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Fatalf("expected permissionDecision deny, got %q", got)
	}
	if got := decoded.HookSpecificOutput.PermissionDecisionReason; got != untrustedFenceCommandReason {
		t.Fatalf("expected nested-policy reason %q, got %q", untrustedFenceCommandReason, got)
	}
}

func TestBuildCodexPreToolUseResponse_WrapsBashCommandWithWrapFlag(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test",
			"description": "Run tests"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--wrap"},
	)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten with --wrap")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if decoded.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected permissionDecision allow, got %q", decoded.HookSpecificOutput.PermissionDecision)
	}

	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "-c", "npm test"})
	if got := decoded.HookSpecificOutput.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
	if got := decoded.HookSpecificOutput.UpdatedInput["description"]; got != "Run tests" {
		t.Fatalf("expected description to be preserved, got %#v", got)
	}
}

func TestBuildCodexPreToolUseResponse_WrapsWithEnvOptIn(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "1")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten when FENCE_CODEX_WRAP=1")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "-c", "npm test"})
	if got := decoded.HookSpecificOutput.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
}

func TestBuildCodexPreToolUseResponse_IgnoresApplyPatch(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "apply_patch",
		"tool_input": {
			"command": "*** Begin Patch\n*** End Patch"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", []string{"--wrap"})
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected apply_patch to be ignored")
	}
}

func TestBuildCodexPreToolUseResponse_SkipsPureCD(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "cd ../repo"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", []string{"--wrap"})
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected pure cd command to be skipped")
	}
}

func TestBuildCodexPreToolUseResponse_SkipsAlreadyFencedCommand(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "/usr/local/bin/fence -c 'npm test'"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", []string{"--wrap"})
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected already-fenced command to be skipped")
	}
}

func TestBuildCodexPreToolUseResponse_IgnoresUnsupportedTool(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "WebSearch",
		"tool_input": {
			"query": "fence sandbox"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected unsupported tool to be ignored")
	}
}

func TestBuildCodexPreToolUseResponse_InvalidJSON(t *testing.T) {
	_, _, err := buildCodexPreToolUseResponse(strings.NewReader(`{`), "/usr/local/bin/fence", nil)
	if err == nil {
		t.Fatal("expected invalid JSON to return an error")
	}
}

func TestBuildCodexPreToolUseResponse_LeavesCommandUnchangedInsideFenceEvenWithWrap(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "1")
	t.Setenv(codexWrapEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	_, changed, err := buildCodexPreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", []string{"--wrap"})
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected command to stay unchanged when already inside Fence")
	}
}

func TestBuildCodexPreToolUseResponse_UsesPinnedSettingsWithWrap(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")
	settingsPath := filepath.Join(t.TempDir(), "fence policy.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--wrap", "--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "--settings", settingsPath, "-c", "npm test"})
	if got := decoded.HookSpecificOutput.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
}

func TestBuildCodexPreToolUseResponse_WrapFlagNotPassedToNestedFence(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--wrap"},
	)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	got, _ := decoded.HookSpecificOutput.UpdatedInput["command"].(string)
	if strings.Contains(got, "--wrap") {
		t.Fatalf("nested fence -c command must not include --wrap, got %q", got)
	}
}

func TestBuildCodexPreToolUseResponse_DeniesBlockedCommandIntentOnly(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")

	settingsPath := filepath.Join(t.TempDir(), "fence.json")
	content := `{
  "command": {
    "deny": ["npm test"],
    "useDefaults": false
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildCodexPreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildCodexPreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected blocked command to produce a deny response")
	}

	var decoded codexPreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if got := decoded.HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Fatalf("expected permissionDecision deny, got %q", got)
	}
	if decoded.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Fatal("expected permissionDecisionReason on deny")
	}
	if decoded.HookSpecificOutput.UpdatedInput != nil {
		t.Fatalf("expected deny response to omit updatedInput, got %#v", decoded.HookSpecificOutput.UpdatedInput)
	}
}

func TestRunCodexPreToolUse_IntentOnlyWritesNothingForAllowedCommand(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	t.Setenv(codexWrapEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	var stdout bytes.Buffer
	if err := runCodexPreToolUse(strings.NewReader(input), &stdout, "/usr/local/bin/fence", nil); err != nil {
		t.Fatalf("runCodexPreToolUse() error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty stdout for intent-only allow, got %q", stdout.String())
	}
}

func TestHooksPrintCmd_PrintsCodexHookConfigWithWrap(t *testing.T) {
	cmd := newHooksPrintCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--codex", "--wrap"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	hooksValue := output["hooks"].(map[string]any)
	preToolUse := hooksValue["PreToolUse"].([]any)
	group := preToolUse[0].(map[string]any)
	nested := group["hooks"].([]any)[0].(map[string]any)

	want := codexHookCommandWithOptions(hookFenceOptions{AllowWrap: true})
	if got := nested["command"]; got != want {
		t.Fatalf("expected wrap-enabled Codex helper command %q, got %#v", want, got)
	}
}

func TestHooksPrintCmd_RejectsWrapWithoutCodex(t *testing.T) {
	cmd := newHooksPrintCmd()
	cmd.SetArgs([]string{"--claude", "--wrap"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --wrap without --codex to fail")
	}
}
