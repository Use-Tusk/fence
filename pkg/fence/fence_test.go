package fence

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeConfigs(t *testing.T) {
	base := &Config{
		Network: NetworkConfig{
			AllowedDomains: []string{"example.com"},
		},
	}
	override := &Config{
		Extends: "base-template",
		Network: NetworkConfig{
			AllowedDomains: []string{"api.example.com"},
		},
	}

	result := MergeConfigs(base, override)
	if result == nil {
		t.Fatal("expected non-nil merged config")
	}
	if result.Extends != "" {
		t.Fatalf("expected Extends to be cleared, got %q", result.Extends)
	}
	if len(result.Network.AllowedDomains) != 2 {
		t.Fatalf("expected 2 allowed domains, got %d: %v", len(result.Network.AllowedDomains), result.Network.AllowedDomains)
	}
}

func TestLoadConfigResolved(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	overridePath := filepath.Join(dir, "override.json")

	if err := os.WriteFile(basePath, []byte(`{
  "network": {
    "allowedDomains": ["example.com"]
  }
}`), 0o600); err != nil {
		t.Fatalf("write base config: %v", err)
	}

	if err := os.WriteFile(overridePath, []byte(`{
  "extends": "./base.json",
  "filesystem": {
    "allowWrite": [".tmp"]
  }
}`), 0o600); err != nil {
		t.Fatalf("write override config: %v", err)
	}

	resolved, err := LoadConfigResolved(overridePath)
	if err != nil {
		t.Fatalf("load resolved config: %v", err)
	}

	if resolved == nil {
		t.Fatal("expected resolved config")
	}
	if resolved.Extends != "" {
		t.Fatalf("expected Extends to be cleared, got %q", resolved.Extends)
	}
	if len(resolved.Network.AllowedDomains) != 1 || resolved.Network.AllowedDomains[0] != "example.com" {
		t.Fatalf("expected inherited allowed domain, got %v", resolved.Network.AllowedDomains)
	}
	if len(resolved.Filesystem.AllowWrite) != 1 || resolved.Filesystem.AllowWrite[0] != ".tmp" {
		t.Fatalf("expected allowWrite to be preserved, got %v", resolved.Filesystem.AllowWrite)
	}
}

func TestPublicConfigSectionTypes(t *testing.T) {
	cfg := &Config{
		MacOS: MacOSConfig{
			Mach: MachConfig{
				Lookup:   []string{"org.chromium.*"},
				Register: []string{"org.chromium.Chromium.MachPortRendezvousServer"},
			},
		},
		Command: CommandConfig{
			Deny:              []string{"git push"},
			RuntimeExecPolicy: RuntimeExecPolicyArgv,
		},
		SSH: SSHConfig{
			AllowedHosts:    []string{"*.example.com"},
			AllowedCommands: []string{"ls"},
		},
	}

	if got := cfg.MacOS.Mach.Lookup[0]; got != "org.chromium.*" {
		t.Fatalf("MacOSConfig/MachConfig lookup = %q, want %q", got, "org.chromium.*")
	}
	if got := cfg.Command.RuntimeExecPolicy; got != RuntimeExecPolicyArgv {
		t.Fatalf("CommandConfig runtime exec policy = %q, want %q", got, RuntimeExecPolicyArgv)
	}
	if got := cfg.SSH.AllowedHosts[0]; got != "*.example.com" {
		t.Fatalf("SSHConfig allowed host = %q, want %q", got, "*.example.com")
	}
}

func TestCheckWritePath(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			AllowWrite: []string{"/workspace"},
			DenyWrite:  []string{"/workspace/secrets"},
		},
	}

	if err := CheckWritePath(cfg, "/workspace/main.go", ""); err != nil {
		t.Fatalf("expected allowWrite path to pass, got %v", err)
	}

	err := CheckWritePath(cfg, "/workspace/secrets/db.json", "")
	if err == nil {
		t.Fatal("expected denyWrite to block")
	}
	var blocked *PathBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected *PathBlockedError, got %T", err)
	}
	if blocked.Op != PathOpWrite || blocked.Reason != "denyWrite" || blocked.MatchedRule != "/workspace/secrets" {
		t.Fatalf("unexpected error fields: %#v", blocked)
	}
}

func TestCheckReadPath(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyRead: []string{"~/.ssh"},
		},
	}

	// Read-mostly mode: everything not deny-masked is readable.
	if err := CheckReadPath(cfg, "/etc/hosts", ""); err != nil {
		t.Fatalf("expected read-mostly mode to allow, got %v", err)
	}

	// strictDenyRead mode: only explicit allowRead entries are readable.
	cfg = &Config{
		Filesystem: FilesystemConfig{
			DefaultDenyRead: true,
			StrictDenyRead:  true,
			AllowRead:       []string{"/workspace"},
		},
	}
	if err := CheckReadPath(cfg, "./notes.txt", "/workspace"); err != nil {
		t.Fatalf("expected allowRead path to pass, got %v", err)
	}

	err := CheckReadPath(cfg, "/usr/lib/something", "")
	if err == nil {
		t.Fatal("expected strictDenyRead to block system path")
	}
	var blocked *PathBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected *PathBlockedError, got %T", err)
	}
	if blocked.Op != PathOpRead || blocked.Reason != "not in allowRead" {
		t.Fatalf("unexpected error fields: %#v", blocked)
	}
}

func TestCheckCommand(t *testing.T) {
	useDefaults := false
	cfg := &Config{
		Command: CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: &useDefaults,
		},
	}

	if err := CheckCommand(cfg, "git status"); err != nil {
		t.Fatalf("expected allowed command to pass, got %v", err)
	}

	// Chained sub-commands are checked individually.
	err := CheckCommand(cfg, "echo ok && git push origin main")
	if err == nil {
		t.Fatal("expected denied command to block")
	}
	var blocked *CommandBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected *CommandBlockedError, got %T", err)
	}
	if blocked.BlockedPrefix != "git push" {
		t.Fatalf("unexpected error fields: %#v", blocked)
	}
}

func TestCheckCommand_SSHPolicy(t *testing.T) {
	cfg := &Config{
		SSH: SSHConfig{
			AllowedHosts: []string{"*.example.com"},
		},
	}

	if err := CheckCommand(cfg, "ssh deploy@web.example.com uptime"); err == nil {
		// allowedCommands is empty → only interactive sessions allowed;
		// a remote command must be blocked.
		t.Fatal("expected remote command to be blocked by SSH policy")
	}

	err := CheckCommand(cfg, "ssh deploy@other.host.net")
	if err == nil {
		t.Fatal("expected disallowed host to be blocked")
	}
	var sshBlocked *SSHBlockedError
	if !errors.As(err, &sshBlocked) {
		t.Fatalf("expected *SSHBlockedError, got %T", err)
	}
}

func TestCheckURL(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			AllowedDomains: []string{"*.example.com"},
			DeniedDomains:  []string{"internal.example.com"},
		},
	}

	if err := CheckURL(cfg, "https://api.example.com/v1/data"); err != nil {
		t.Fatalf("expected allowed domain to pass, got %v", err)
	}

	// Deny rules win over allow rules.
	err := CheckURL(cfg, "https://internal.example.com/admin")
	if err == nil {
		t.Fatal("expected denied domain to block")
	}
	var blocked *URLBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected *URLBlockedError, got %T", err)
	}
	if blocked.Host != "internal.example.com" || blocked.Reason != "deniedDomains" || blocked.MatchedRule != "internal.example.com" {
		t.Fatalf("unexpected error fields: %#v", blocked)
	}

	// Empty allowedDomains denies everything.
	if err := CheckURL(&Config{}, "https://example.com/"); err == nil {
		t.Fatal("expected empty policy to deny")
	}
}
