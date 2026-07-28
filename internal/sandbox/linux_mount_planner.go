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
	Path string
	Kind linuxLateMountKind
}

type linuxLateMountPlanner struct {
	mounts []linuxLateMount
}

func newLinuxLateMountPlanner() *linuxLateMountPlanner {
	return &linuxLateMountPlanner{}
}

func (p *linuxLateMountPlanner) Add(path string, kind linuxLateMountKind) {
	path = filepath.Clean(path)
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

	p.mounts = append(p.mounts, linuxLateMount{Path: path, Kind: kind})
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
			args = append(args, "--ro-bind", mount.Path, mount.Path)
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
				for _, grantPath := range explicitlyReadableDescendants(cfg, mountPath) {
					planner.Add(grantPath, linuxLateMountReadOnlyExempt)
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

// explicitlyReadableDescendants returns the resolved paths strictly under dir
// that the config explicitly grants read access to (allowWrite grants read, so
// it counts here too).
//
// denyRead is re-checked per path rather than relying on the planner's masked
// ancestor rule: exempt mounts deliberately punch through a masked directory,
// so a denied path must be filtered out here or the mask would leak.
func explicitlyReadableDescendants(cfg *config.Config, dir string) []string {
	if cfg == nil {
		return nil
	}

	patterns := slices.Concat(
		cfg.Filesystem.AllowRead,
		cfg.Filesystem.AllowExecute,
		cfg.Filesystem.AllowWrite,
	)

	var paths []string
	seen := make(map[string]bool)
	for _, path := range ExpandGlobPatterns(patterns) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		mountPath = filepath.Clean(mountPath)
		if mountPath == dir || !linuxPathContains(dir, mountPath) || seen[mountPath] {
			continue
		}
		if _, denied := matchPathRule(path, cfg.Filesystem.DenyRead); denied {
			continue
		}
		if _, denied := matchPathRule(mountPath, cfg.Filesystem.DenyRead); denied {
			continue
		}
		seen[mountPath] = true
		paths = append(paths, mountPath)
	}
	return paths
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
