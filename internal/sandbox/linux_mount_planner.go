//go:build linux

package sandbox

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/fencesandbox/fence/internal/config"
	"github.com/fencesandbox/fence/internal/fencelog"
)

type linuxLateMountKind int

const (
	linuxLateMountReadOnly linuxLateMountKind = iota
	linuxLateMountMaskFile
	linuxLateMountMaskDir
	// linuxLateMountReadOnlyExempt is a read-only bind that survives a masked
	// ancestor directory. Masking a dangerous directory is a write protection
	// for the directory itself; it must not silently revoke reads the policy
	// explicitly granted inside it. Callers are responsible for only exempting
	// paths denyRead does not cover.
	linuxLateMountReadOnlyExempt
)

type linuxLateMount struct {
	// Path is where the mount lands inside the sandbox.
	Path string
	// Source is the host path bound at Path. It only differs from Path for
	// exempt binds of granted symlinks, where the resolved target has to show
	// up under the name the policy granted.
	Source string
	Kind   linuxLateMountKind
}

type linuxLateMountPlanner struct {
	mounts []linuxLateMount
}

func newLinuxLateMountPlanner() *linuxLateMountPlanner {
	return &linuxLateMountPlanner{}
}

func (p *linuxLateMountPlanner) Add(path string, kind linuxLateMountKind) {
	p.add(path, path, kind)
}

// AddExempt plans a read-only bind that survives a masked ancestor directory.
// source is the resolved host path; path is where it is exposed inside the
// sandbox. The two differ when the granted path is a symlink: binding only the
// canonical target would leave the granted name itself buried under the mask.
func (p *linuxLateMountPlanner) AddExempt(source, path string) {
	p.add(source, path, linuxLateMountReadOnlyExempt)
}

func (p *linuxLateMountPlanner) add(source, path string, kind linuxLateMountKind) {
	path = filepath.Clean(path)
	source = filepath.Clean(source)
	if path == "" || path == "." {
		return
	}

	// A read-only self-bind under a masked directory would puncture the mask.
	// Masks under a masked directory are kept instead of dropped here: an exempt
	// bind added later can re-expose the subtree they live in, and then they are
	// what keeps denyRead winning. Mounts() drops the ones that stay redundant.
	if kind == linuxLateMountReadOnly && p.hasStrictAncestor(path, linuxLateMountMaskDir) {
		return
	}

	for i, existing := range p.mounts {
		if existing.Path != path {
			continue
		}
		if linuxLateMountPriority(existing.Kind) >= linuxLateMountPriority(kind) {
			return
		}

		p.mounts[i].Kind = kind
		p.mounts[i].Source = source
		switch kind {
		case linuxLateMountMaskDir:
			p.removeDescendants(path, func(mount linuxLateMount) bool {
				return mount.Kind == linuxLateMountReadOnly
			})
		case linuxLateMountReadOnly:
			p.removeDescendants(path, func(mount linuxLateMount) bool {
				return mount.Kind == linuxLateMountReadOnly
			})
		}
		return
	}

	if kind == linuxLateMountReadOnly && p.hasStrictAncestor(path, linuxLateMountReadOnly) {
		return
	}

	switch kind {
	case linuxLateMountMaskDir:
		p.removeDescendants(path, func(mount linuxLateMount) bool {
			return mount.Kind == linuxLateMountReadOnly
		})
	case linuxLateMountReadOnly:
		p.removeDescendants(path, func(mount linuxLateMount) bool {
			return mount.Kind == linuxLateMountReadOnly
		})
	}

	p.mounts = append(p.mounts, linuxLateMount{Path: path, Source: source, Kind: kind})
}

func (p *linuxLateMountPlanner) hasStrictAncestor(path string, kind linuxLateMountKind) bool {
	for _, mount := range p.mounts {
		if mount.Kind != kind || mount.Path == path {
			continue
		}
		if linuxPathContains(mount.Path, path) {
			return true
		}
	}
	return false
}

// isRedundantMask reports whether a mask mount is already covered by a masked
// ancestor directory. It is not redundant when an exempt bind sits between the
// two: that bind re-exposes the host subtree, so the mask is the only thing
// still hiding the path. Sorting by depth then puts the mask after the bind it
// has to override.
func (p *linuxLateMountPlanner) isRedundantMask(mount linuxLateMount) bool {
	if mount.Kind != linuxLateMountMaskFile && mount.Kind != linuxLateMountMaskDir {
		return false
	}

	maskDir, masked := p.deepestStrictAncestor(mount.Path, linuxLateMountMaskDir)
	if !masked {
		return false
	}
	exempt, exempted := p.deepestStrictAncestor(mount.Path, linuxLateMountReadOnlyExempt)
	return !exempted || !linuxPathContains(maskDir, exempt)
}

func (p *linuxLateMountPlanner) deepestStrictAncestor(path string, kind linuxLateMountKind) (string, bool) {
	best := ""
	found := false
	for _, mount := range p.mounts {
		if mount.Kind != kind || mount.Path == path {
			continue
		}
		if !linuxPathContains(mount.Path, path) {
			continue
		}
		if !found || linuxLateMountDepth(mount.Path) > linuxLateMountDepth(best) {
			best = mount.Path
			found = true
		}
	}
	return best, found
}

func (p *linuxLateMountPlanner) removeDescendants(path string, shouldRemove func(linuxLateMount) bool) {
	filtered := p.mounts[:0]
	for _, mount := range p.mounts {
		if mount.Path != path && linuxPathContains(path, mount.Path) && shouldRemove(mount) {
			continue
		}
		filtered = append(filtered, mount)
	}
	p.mounts = filtered
}

func (p *linuxLateMountPlanner) Mounts() []linuxLateMount {
	mounts := make([]linuxLateMount, 0, len(p.mounts))
	for _, mount := range p.mounts {
		if p.isRedundantMask(mount) {
			continue
		}
		mounts = append(mounts, mount)
	}
	slices.SortFunc(mounts, func(a, b linuxLateMount) int {
		depthA := linuxLateMountDepth(a.Path)
		depthB := linuxLateMountDepth(b.Path)
		if depthA != depthB {
			return depthA - depthB
		}
		return strings.Compare(a.Path, b.Path)
	})
	return mounts
}

func appendLinuxLateMounts(args []string, mounts []linuxLateMount) []string {
	for _, mount := range mounts {
		switch mount.Kind {
		case linuxLateMountMaskDir:
			args = append(args, "--tmpfs", mount.Path)
		case linuxLateMountMaskFile:
			args = append(args, "--ro-bind", "/dev/null", mount.Path)
		case linuxLateMountReadOnly, linuxLateMountReadOnlyExempt:
			source := mount.Source
			if source == "" {
				source = mount.Path
			}
			args = append(args, "--ro-bind", source, mount.Path)
		}
	}
	return args
}

func linuxLateMountPriority(kind linuxLateMountKind) int {
	switch kind {
	case linuxLateMountMaskDir:
		return 3
	case linuxLateMountMaskFile:
		return 2
	case linuxLateMountReadOnly, linuxLateMountReadOnlyExempt:
		return 1
	default:
		return 0
	}
}

func linuxLateMountDepth(path string) int {
	path = filepath.Clean(path)
	trimmed := strings.Trim(path, string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, string(filepath.Separator)) + 1
}

func linuxPathContains(ancestor, path string) bool {
	ancestor = filepath.Clean(ancestor)
	path = filepath.Clean(path)

	if ancestor == path {
		return true
	}
	if ancestor == string(filepath.Separator) {
		return strings.HasPrefix(path, string(filepath.Separator))
	}
	return strings.HasPrefix(path, ancestor+string(filepath.Separator))
}

func collectResolvedLinuxLateMountPaths(patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)
	for _, path := range ExpandGlobPatterns(patterns) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		mountPath = filepath.Clean(mountPath)
		if seen[mountPath] {
			continue
		}
		seen[mountPath] = true
		paths = append(paths, mountPath)
	}
	return paths
}

// appendLinuxLatePolicyMounts plans the final policy overlays with subtree-aware
// precedence so masked directories cannot be punctured by later self-binds.
func appendLinuxLatePolicyMounts(
	bwrapArgs []string,
	cfg *config.Config,
	cwd string,
	defaultDenyRead bool,
	deniedExecPaths []string,
	debug bool,
) []string {
	planner := newLinuxLateMountPlanner()

	if cfg != nil {
		for _, mountPath := range collectResolvedLinuxLateMountPaths(cfg.Filesystem.DenyRead) {
			if isDirectory(mountPath) {
				planner.Add(mountPath, linuxLateMountMaskDir)
			} else {
				planner.Add(mountPath, linuxLateMountMaskFile)
			}
		}
	}

	allowGitConfig := cfg != nil && cfg.Filesystem.AllowGitConfig
	for _, path := range getMandatoryDenyPaths(cwd, allowGitConfig) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		// Dangerous-path protection is a write concept: shell startup files
		// stay readable, they just cannot be written (see CheckReadPath, which
		// deliberately skips dangerous paths). A read-only self-bind expresses
		// that. In defaultDenyRead mode the same bind would also *expose* a
		// path the read policy never granted — root is not bound there — so
		// those get masked instead of rebound.
		if defaultDenyRead && !readableUnderPolicy(cfg, path, mountPath) {
			if isDirectory(mountPath) {
				planner.Add(mountPath, linuxLateMountMaskDir)
				// The mask hides the whole subtree, including binds emitted
				// earlier for allowRead rules that only name files *inside* the
				// directory. Re-mount those on top of the tmpfs so the grant
				// survives; everything else in the directory stays hidden, and
				// the read-only bind keeps it unwritable.
				for _, grant := range explicitlyReadableDescendants(cfg, path, mountPath) {
					planner.AddExempt(grant.Source, grant.Path)
				}
			} else {
				planner.Add(mountPath, linuxLateMountMaskFile)
			}
			continue
		}
		planner.Add(mountPath, linuxLateMountReadOnly)
	}

	if cfg != nil {
		for _, mountPath := range collectResolvedLinuxLateMountPaths(cfg.Filesystem.DenyWrite) {
			planner.Add(mountPath, linuxLateMountReadOnly)
		}
	}

	for _, path := range deniedExecPaths {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			if debug {
				fencelog.Printf("[fence:linux] Skipping runtime exec deny mount for %s (unmountable)\n", path)
			}
			continue
		}
		planner.Add(mountPath, linuxLateMountMaskFile)
	}

	return appendLinuxLateMounts(bwrapArgs, planner.Mounts())
}

// linuxGrantAlias is a granted path whose own spelling is a symlink: Source is
// the resolved host path, Path is the name the policy used.
type linuxGrantAlias struct {
	Source string
	Path   string
}

// linuxSymlinkGrantAliases returns the aliases needed for granted patterns that
// name a symlink. Mounts are made at canonical paths, so without an alias the
// granted name is missing inside the sandbox. Patterns matched by the caller's
// deny list are skipped: an alias must never expose a path at a name the deny
// rules cover, since the deny mounts land on the canonical path only.
func linuxSymlinkGrantAliases(patterns, denied []string) []linuxGrantAlias {
	var aliases []linuxGrantAlias
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		if ContainsGlobChars(pattern) {
			continue
		}
		lexical := filepath.Clean(NormalizePathLexical(pattern))
		resolved, ok := resolvePathForMount(lexical)
		if !ok {
			continue
		}
		resolved = filepath.Clean(resolved)
		if resolved == lexical || seen[lexical] {
			continue
		}
		if _, deny := matchPathRule(lexical, denied); deny {
			continue
		}
		if _, deny := matchPathRule(resolved, denied); deny {
			continue
		}
		seen[lexical] = true
		aliases = append(aliases, linuxGrantAlias{Source: resolved, Path: lexical})
	}
	return aliases
}

// expandGrantPatterns expands the configured patterns without canonicalizing
// the plain ones. ExpandGlobPatterns resolves symlinks, which is what the mount
// source needs but hides the path the policy actually named — and that name is
// what a mask has to be punctured at.
func expandGrantPatterns(patterns []string) []string {
	var expanded []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		var paths []string
		if ContainsGlobChars(pattern) {
			paths = ExpandGlobPatterns([]string{pattern})
		} else {
			paths = []string{NormalizePathLexical(pattern)}
		}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			expanded = append(expanded, path)
		}
	}
	return expanded
}

// linuxLateMountExemption is a grant that has to be re-exposed on top of a
// masked directory: Source is the resolved host path, Path is the granted
// location inside the sandbox.
type linuxLateMountExemption struct {
	Source string
	Path   string
}

// explicitlyReadableDescendants returns the grants strictly under a masked
// directory that the config explicitly gives read access to (allowWrite grants
// read, so it counts here too). lexicalDir is the directory as the policy spells
// it and dir is its resolved form; a grant counts when either spelling puts it
// inside, because either one is what the mask hides.
//
// The granted path is kept as the mount destination instead of its canonical
// target: a symlink under the mask only stays reachable if the resolved file is
// bound back at the link's own path.
//
// denyRead is re-checked per path rather than relying on the planner's masked
// ancestor rule: exempt mounts deliberately punch through a masked directory,
// so a denied path must be filtered out here or the mask would leak.
func explicitlyReadableDescendants(cfg *config.Config, lexicalDir, dir string) []linuxLateMountExemption {
	if cfg == nil {
		return nil
	}

	lexicalDir = filepath.Clean(lexicalDir)
	patterns := slices.Concat(
		cfg.Filesystem.AllowRead,
		cfg.Filesystem.AllowExecute,
		cfg.Filesystem.AllowWrite,
	)

	var grants []linuxLateMountExemption
	seen := make(map[string]bool)
	for _, path := range expandGrantPatterns(patterns) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		mountPath = filepath.Clean(mountPath)

		grantPath := filepath.Clean(path)
		switch {
		case grantPath != lexicalDir && linuxPathContains(lexicalDir, grantPath):
		case mountPath != dir && linuxPathContains(dir, mountPath):
			grantPath = mountPath
		default:
			continue
		}
		if seen[grantPath] {
			continue
		}
		if _, denied := matchPathRule(path, cfg.Filesystem.DenyRead); denied {
			continue
		}
		if _, denied := matchPathRule(mountPath, cfg.Filesystem.DenyRead); denied {
			continue
		}
		seen[grantPath] = true
		grants = append(grants, linuxLateMountExemption{Source: mountPath, Path: grantPath})
	}
	return grants
}

// readableUnderPolicy reports whether the config explicitly grants read access
// to any of the given spellings of a path. Callers pass both the policy-facing
// path and its symlink-resolved mount path: a rule like allowRead
// "~/dotfiles/*" only matches the resolved target, while "~/.zshrc" normalizes
// to the target and matches either way.
//
// Only explicit grants count. The default readable system paths are
// deliberately excluded: some of them (notably /tmp) are replaced by a tmpfs
// in defaultDenyRead mode, so a self-bind there would surface a host file the
// sandbox never had. denyRead always wins.
func readableUnderPolicy(cfg *config.Config, paths ...string) bool {
	if cfg == nil {
		return false
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, denied := matchPathRule(path, cfg.Filesystem.DenyRead); denied {
			return false
		}
	}
	// allowWrite grants read, mirroring CheckReadPath's allow tiers.
	grants := [][]string{
		cfg.Filesystem.AllowRead,
		cfg.Filesystem.AllowExecute,
		cfg.Filesystem.AllowWrite,
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		for _, rules := range grants {
			if _, ok := matchPathRule(path, rules); ok {
				return true
			}
		}
	}
	return false
}
