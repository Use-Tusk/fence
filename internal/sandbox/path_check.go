package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/fencesandbox/fence/internal/config"
)

// PathOp identifies the filesystem operation a path check evaluates.
type PathOp string

const (
	PathOpRead  PathOp = "read"
	PathOpWrite PathOp = "write"
)

// PathBlockedError is returned when access to a path is blocked by the
// filesystem policy. Callers can `errors.As` to inspect MatchedRule.
type PathBlockedError struct {
	Path        string
	Op          PathOp // "read" or "write"
	MatchedRule string // empty when default-deny ("not in allowWrite" / "not in allowRead")
	Reason      string // "denyWrite", "denyRead", "dangerous path", "not in allowWrite", ...
}

func (e *PathBlockedError) Error() string {
	verb := "write to"
	if e.Op == PathOpRead {
		verb = "read of"
	}
	if e.MatchedRule == "" {
		return fmt.Sprintf("%s %q blocked by sandbox filesystem policy: %s", verb, e.Path, e.Reason)
	}
	return fmt.Sprintf("%s %q blocked by sandbox filesystem policy: %s (matched %q)", verb, e.Path, e.Reason, e.MatchedRule)
}

// CheckWritePath is the hook-time predicate paralleling the wrap-mode profile
// generators (macOS seatbelt, Linux landlock). Both consume cfg.Filesystem.*
// plus DangerousFiles / DangerousDirectories, so a single fence.json behaves
// the same in both modes: a write is allowed iff it matches allowWrite and
// neither denyWrite nor a dangerous-path rule. allowWrite entries are exact
// or subtree matches (mirroring seatbelt's `(allow file-write* (subpath ...))`);
// glob patterns use doublestar.
//
// `cwd` is required when path is relative; pass "" to require absolute paths.
//
// Adapters that want hook-mode to be permissive when filesystem policy is
// unconfigured should ship a template (see internal/templates/hermes.json
// for a worked example) rather than relaxing this predicate. Write
// semantics are identical in hook-mode and wrap-mode; read semantics have
// one deliberate exception: macOS wrap-mode in permissive mode re-allows
// explicit allowRead paths over a denyRead subtree (see CheckReadPath),
// which hook-mode preflight intentionally does not reflect.
func CheckWritePath(path string, cwd string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}
	clean, err := absoluteCleanPath(path, cwd)
	if err != nil {
		return &PathBlockedError{Path: path, Op: PathOpWrite, Reason: err.Error()}
	}

	if rule, ok := matchesDangerousPath(clean); ok {
		return &PathBlockedError{Path: clean, Op: PathOpWrite, MatchedRule: rule, Reason: "dangerous path"}
	}

	if rule, ok := matchPathRule(clean, cfg.Filesystem.DenyWrite); ok {
		return &PathBlockedError{Path: clean, Op: PathOpWrite, MatchedRule: rule, Reason: "denyWrite"}
	}

	if _, ok := matchPathRule(clean, cfg.Filesystem.AllowWrite); ok {
		return nil
	}

	return &PathBlockedError{Path: clean, Op: PathOpWrite, Reason: "not in allowWrite"}
}

// CheckReadPath is the read-side policy predicate paralleling the wrap-mode
// profile generators. It is intentionally platform-agnostic and keeps
// denyRead always winning, even though macOS wrap-mode seatbelt re-allows
// explicit allowRead paths inside a denyRead subtree in permissive mode
// (see generateReadRules) - preflight does not reflect that override:
//
//  1. denyRead always wins, in both read modes, on all platforms.
//  2. Without defaultDenyRead (read-mostly mode), everything else is
//     readable.
//  3. With defaultDenyRead (implied by strictDenyRead), a path is readable
//     when it matches allowRead, allowExecute, or allowWrite (allowWrite
//     grants read), or one of the default readable system paths unless
//     strictDenyRead suppresses those.
//
// Dangerous-path protection is intentionally absent here: it is a write
// concept (shell startup files stay readable, just not writable).
//
// `cwd` is required when path is relative; pass "" to require absolute paths.
func CheckReadPath(path string, cwd string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}
	clean, err := absoluteCleanPath(path, cwd)
	if err != nil {
		return &PathBlockedError{Path: path, Op: PathOpRead, Reason: err.Error()}
	}

	if rule, ok := matchPathRule(clean, cfg.Filesystem.DenyRead); ok {
		return &PathBlockedError{Path: clean, Op: PathOpRead, MatchedRule: rule, Reason: "denyRead"}
	}

	// strictDenyRead implies defaultDenyRead; handle configs that were not
	// run through config.Validate (which normalizes this).
	defaultDenyRead := cfg.Filesystem.DefaultDenyRead || cfg.Filesystem.StrictDenyRead
	if !defaultDenyRead {
		return nil
	}

	if _, ok := matchPathRule(clean, cfg.Filesystem.AllowRead); ok {
		return nil
	}
	if _, ok := matchPathRule(clean, cfg.Filesystem.AllowExecute); ok {
		return nil
	}
	// allowWrite implies read (documented; Landlock grants read+write,
	// Linux binds allowWrite paths read-write in defaultDenyRead mode).
	if _, ok := matchPathRule(clean, cfg.Filesystem.AllowWrite); ok {
		return nil
	}

	if !cfg.Filesystem.StrictDenyRead {
		if _, ok := matchPathRule(clean, GetDefaultReadablePaths()); ok {
			return nil
		}
	}

	return &PathBlockedError{Path: clean, Op: PathOpRead, Reason: "not in allowRead"}
}

// absoluteCleanPath resolves path against cwd when relative. "../" escapes
// are allowed — the policy rules decide if the resolved location is reachable.
func absoluteCleanPath(path, cwd string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if cwd == "" {
		return "", fmt.Errorf("relative path %q without cwd", path)
	}
	if !filepath.IsAbs(cwd) {
		return "", fmt.Errorf("cwd %q is not absolute", cwd)
	}
	return filepath.Clean(filepath.Join(cwd, path)), nil
}

// matchPathRule returns (rule, true) when path matches one of rules.
// Each rule is normalized via NormalizePath before matching: tildes
// expand to $HOME, relative paths resolve against cwd, and symlinks
// resolve where possible. Wrap-mode generators do the same thing, so
// templates like "~/.hermes/**" behave identically in both modes.
//
//   - Globs (rule contains *, ?, [, {): doublestar.Match.
//   - Plain paths: exact or subtree match (path == rule, or path
//     starts with rule + "/", anchored at a component boundary).
//
// The original rule string is returned in MatchedRule so deny messages
// echo what the user actually wrote, not the post-expansion path.
func matchPathRule(path string, rules []string) (string, bool) {
	for _, rule := range rules {
		if rule == "" {
			continue
		}
		normalized := NormalizePath(rule)
		if hasGlobMeta(normalized) {
			if matched, err := doublestar.Match(normalized, path); err == nil && matched {
				return rule, true
			}
			continue
		}
		clean := filepath.Clean(normalized)
		if !filepath.IsAbs(clean) {
			// NormalizePath should always produce an absolute path
			// for non-glob rules, but defend against edge cases
			// (empty cwd, etc.).
			continue
		}
		if path == clean {
			return rule, true
		}
		// Anchor subtree match at a component boundary; "/" is already
		// its own separator suffix.
		prefix := clean
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if strings.HasPrefix(path, prefix) {
			return rule, true
		}
	}
	return "", false
}

func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', '{':
			return true
		}
	}
	return false
}

// matchesDangerousPath returns (rule, true) when path is a dangerous file
// (basename match against DangerousFiles), inside a dangerous directory, or
// inside .git/hooks / .git/config. Always wins over allowWrite, mirroring
// the wrap-mode profile generators.
func matchesDangerousPath(path string) (string, bool) {
	base := filepath.Base(path)
	for _, name := range DangerousFiles {
		if base == name {
			return name, true
		}
	}

	// .git internals: hooks/* and config only. The rest of .git stays
	// writable so git itself can update HEAD/refs/objects.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] != ".git" {
			continue
		}
		next := parts[i+1]
		if next == "hooks" {
			return ".git/hooks", true
		}
		if next == "config" && i == len(parts)-2 {
			return ".git/config", true
		}
	}

	for _, dir := range DangerousDirectories {
		if pathInDangerousDir(path, dir) {
			return dir, true
		}
	}
	return "", false
}

// pathInDangerousDir matches single-component (".vscode") and multi-component
// ("a/b") entries at any path-component boundary, so "notvscode" won't
// match ".vscode".
func pathInDangerousDir(path, dir string) bool {
	dirParts := strings.Split(filepath.ToSlash(dir), "/")
	pathParts := strings.Split(filepath.ToSlash(path), "/")

	if len(pathParts) <= len(dirParts) {
		return false
	}

	for start := 0; start <= len(pathParts)-len(dirParts)-1; start++ {
		match := true
		for i, want := range dirParts {
			if pathParts[start+i] != want {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
