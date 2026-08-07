// Package fence provides a public API for sandboxing commands.
package fence

import (
	"github.com/fencesandbox/fence/internal/config"
	"github.com/fencesandbox/fence/internal/platform"
	"github.com/fencesandbox/fence/internal/proxy"
	"github.com/fencesandbox/fence/internal/sandbox"
	"github.com/fencesandbox/fence/internal/templates"
)

// IsSupported returns true if the current platform supports sandboxing (macOS/Linux).
func IsSupported() bool {
	return platform.IsSupported()
}

// DispatchInternalHelper handles Fence's private process modes. Applications
// that configure their own executable with Manager.SetLinuxHelperPath must call
// this before their normal flag parsing and exit with the returned code when
// handled is true.
func DispatchInternalHelper(args []string) (handled bool, exitCode int, err error) {
	return sandbox.DispatchInternalHelper(args)
}

// Config is the configuration for fence.
type Config = config.Config

// NetworkConfig defines network restrictions.
type NetworkConfig = config.NetworkConfig

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig = config.FilesystemConfig

// DevicesConfig defines device exposure inside the sandbox.
type DevicesConfig = config.DevicesConfig

// DeviceMode controls how /dev is set up inside Linux sandboxes.
type DeviceMode = config.DeviceMode

const (
	DeviceModeAuto    DeviceMode = config.DeviceModeAuto
	DeviceModeMinimal DeviceMode = config.DeviceModeMinimal
	DeviceModeHost    DeviceMode = config.DeviceModeHost
)

// MacOSConfig defines macOS-specific sandbox controls.
type MacOSConfig = config.MacOSConfig

// MachConfig defines additional Mach/XPC permissions for macOS sandboxes.
type MachConfig = config.MachConfig

// CommandConfig defines command restrictions.
type CommandConfig = config.CommandConfig

// RuntimeExecPolicy controls how Linux runtime child-process execs are enforced.
type RuntimeExecPolicy = config.RuntimeExecPolicy

const (
	RuntimeExecPolicyPath RuntimeExecPolicy = config.RuntimeExecPolicyPath
	RuntimeExecPolicyArgv RuntimeExecPolicy = config.RuntimeExecPolicyArgv
)

// ErrLinuxHelperRequired is returned when Linux wrapping is requested without
// configuring a compatible helper executable.
var ErrLinuxHelperRequired = sandbox.ErrLinuxHelperRequired

// SSHConfig defines SSH command restrictions.
type SSHConfig = config.SSHConfig

// Manager handles sandbox initialization and command wrapping.
type Manager = sandbox.Manager

// ServiceOptions describes the sandboxed service's inbound-connectivity model.
// See Manager.SetService.
type ServiceOptions = sandbox.ServiceOptions

// ExposedPort describes a single host-facing port exposure with an explicit
// bind address. See ServiceOptions.Exposures.
type ExposedPort = sandbox.ExposedPort

// DefaultExposedBindAddress is the default host interface for reverse-bridge
// listeners (loopback only). Set ExposedPort.BindAddress to "0.0.0.0" or a
// specific interface address to opt into wider exposure.
const DefaultExposedBindAddress = sandbox.DefaultExposedBindAddress

// LoopbackPort is a sugar constructor for the common case: expose a port on
// the host loopback interface.
func LoopbackPort(port int) ExposedPort {
	return sandbox.LoopbackPort(port)
}

// ServiceExecutionModel selects the port-binding workflow fence should assume
// for the sandboxed service.
type ServiceExecutionModel = sandbox.ServiceExecutionModel

const (
	// ServiceBindsInSandbox indicates the sandboxed process itself binds
	// the exposed port inside the sandbox (default).
	ServiceBindsInSandbox ServiceExecutionModel = sandbox.ServiceBindsInSandbox

	// ServiceBindsOnHost indicates the sandboxed process delegates port
	// binding to an external daemon (docker, podman, systemctl, …) whose
	// listener lives outside the sandbox network namespace.
	ServiceBindsOnHost ServiceExecutionModel = sandbox.ServiceBindsOnHost
)

// NewManager creates a new sandbox manager.
// If debug is true, verbose logging is enabled.
// If monitor is true, only violations (blocked requests) are logged.
func NewManager(cfg *Config, debug, monitor bool) *Manager {
	return sandbox.NewManager(cfg, debug, monitor)
}

// DefaultConfig returns the default configuration with all network blocked.
func DefaultConfig() *Config {
	return config.Default()
}

// LoadConfig loads configuration from a file.
func LoadConfig(path string) (*Config, error) {
	return config.Load(path)
}

// LoadConfigResolved loads configuration from a file and resolves any extends
// entries relative to that file's parent directory.
func LoadConfigResolved(path string) (*Config, error) {
	cfg, err := config.Load(path)
	if err != nil || cfg == nil {
		return cfg, err
	}
	return templates.ResolveExtendsFromPath(cfg, path)
}

// MergeConfigs combines a base config with an override config.
func MergeConfigs(base, override *Config) *Config {
	return config.Merge(base, override)
}

// DefaultConfigPath returns the canonical config path for new configs.
func DefaultConfigPath() string {
	return config.DefaultConfigPath()
}

// ResolveDefaultConfigPath returns the config path fence should load by default.
func ResolveDefaultConfigPath() string {
	return config.ResolveDefaultConfigPath()
}

// ResolveConfigPath returns the config path fence would load when --settings is
// not provided, preferring the nearest project fence.jsonc (or fence.json)
// before the user default config path.
func ResolveConfigPath(startDir string) (string, error) {
	return config.ResolveConfigPath(startDir)
}

// PathOp identifies the filesystem operation a path check evaluates.
type PathOp = sandbox.PathOp

const (
	PathOpRead  PathOp = sandbox.PathOpRead
	PathOpWrite PathOp = sandbox.PathOpWrite
)

// PathBlockedError is the typed error returned by CheckReadPath and
// CheckWritePath when a path is blocked. Use errors.As to inspect the
// cleaned path, operation, matched rule, and reason.
type PathBlockedError = sandbox.PathBlockedError

// CheckReadPath reports whether cfg's filesystem policy permits reading
// path. A nil error means the read is allowed; a non-nil error is always a
// *PathBlockedError describing why it is denied.
//
// This is a policy preflight, not enforcement: it evaluates the same rules
// the sandbox profile generators consume (denyRead, defaultDenyRead,
// strictDenyRead, allowRead, allowExecute, allowWrite-implies-read, and the
// default readable system paths), but it does not sandbox anything and the
// kernel-level sandbox remains authoritative. denyRead always wins here on
// all platforms — macOS wrap-mode seatbelt (permissive mode only) re-allows
// explicit allowRead paths inside a denyRead subtree (see generateReadRules);
// preflight intentionally does not reflect that override. It evaluates the
// declared path lexically and does not resolve symlinks on the target.
//
// Relative paths resolve against cwd; pass "" to require absolute paths.
func CheckReadPath(cfg *Config, path, cwd string) error {
	return sandbox.CheckReadPath(path, cwd, cfg)
}

// CheckWritePath reports whether cfg's filesystem policy permits writing
// path. A nil error means the write is allowed; a non-nil error is always a
// *PathBlockedError describing why it is denied.
//
// Precedence matches wrap-mode enforcement: mandatory dangerous-path
// protection, then denyWrite, then allowWrite, then default deny. Like
// CheckReadPath, this is a policy preflight, not enforcement.
//
// Relative paths resolve against cwd; pass "" to require absolute paths.
func CheckWritePath(cfg *Config, path, cwd string) error {
	return sandbox.CheckWritePath(path, cwd, cfg)
}

// CommandBlockedError is the typed error returned by CheckCommand when a
// command matches a deny rule. Use errors.As to inspect the offending
// command and the deny prefix it matched.
type CommandBlockedError = sandbox.CommandBlockedError

// SSHBlockedError is the typed error returned by CheckCommand when an ssh
// invocation violates the SSH policy (allowedHosts, allowedCommands, ...).
type SSHBlockedError = sandbox.SSHBlockedError

// CheckCommand reports whether cfg's command policy permits a shell
// command. A nil error means the command is allowed; a non-nil error is a
// *CommandBlockedError (or *SSHBlockedError for ssh policy violations).
//
// The parser understands pipelines, `&&`/`||`/`;` chains, and nested
// `sh -c` / `bash -c` patterns, so each sub-command is checked — the same
// preflight WrapCommand performs, without requiring a Manager or starting
// any proxies.
func CheckCommand(cfg *Config, command string) error {
	return sandbox.CheckCommand(command, cfg)
}

// URLBlockedError is the typed error returned by CheckURL. Use errors.As
// to inspect the URL, extracted host, matched rule, and reason.
type URLBlockedError = proxy.URLBlockedError

// CheckURL reports whether cfg's network policy permits a URL. A nil error
// means the URL's host matches allowedDomains and not deniedDomains; an
// empty allowedDomains denies everything. Deny rules win, and "*" in
// allowedDomains allows any host not explicitly denied.
//
// This is an intent check on the declared URL, strictly weaker than the
// traffic-time proxy enforcement wrapped commands get: redirects, embedded
// URLs, and requests made by the fetched content are not covered. Use it
// to preflight tools that fetch outside the sandbox, not as a substitute
// for wrapping them.
func CheckURL(cfg *Config, rawURL string) error {
	return proxy.CheckURL(rawURL, cfg)
}
