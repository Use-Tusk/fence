package sandbox

import (
	"fmt"
	"os"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/proxy"
)

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config        *config.Config
	httpProxy     *proxy.HTTPProxy
	socksProxy    *proxy.SOCKSProxy
	linuxBridge   *LinuxBridge
	reverseBridge *ReverseBridge
	httpPort      int
	socksPort     int
	exposedPorts  []int
	debug         bool
	initialized   bool
}

// NewManager creates a new sandbox manager.
func NewManager(cfg *config.Config, debug bool) *Manager {
	return &Manager{
		config: cfg,
		debug:  debug,
	}
}

// SetExposedPorts sets the ports to expose for inbound connections.
func (m *Manager) SetExposedPorts(ports []int) {
	m.exposedPorts = ports
}

// Initialize sets up the sandbox infrastructure (proxies, etc.).
func (m *Manager) Initialize() error {
	if m.initialized {
		return nil
	}

	if !platform.IsSupported() {
		return fmt.Errorf("sandbox is not supported on platform: %s", platform.Detect())
	}

	filter := proxy.CreateDomainFilter(m.config, m.debug)

	m.httpProxy = proxy.NewHTTPProxy(filter, m.debug)
	httpPort, err := m.httpProxy.Start()
	if err != nil {
		return fmt.Errorf("failed to start HTTP proxy: %w", err)
	}
	m.httpPort = httpPort

	m.socksProxy = proxy.NewSOCKSProxy(filter, m.debug)
	socksPort, err := m.socksProxy.Start()
	if err != nil {
		m.httpProxy.Stop()
		return fmt.Errorf("failed to start SOCKS proxy: %w", err)
	}
	m.socksPort = socksPort

	// On Linux, set up the socat bridges
	if platform.Detect() == platform.Linux {
		bridge, err := NewLinuxBridge(m.httpPort, m.socksPort, m.debug)
		if err != nil {
			m.httpProxy.Stop()
			m.socksProxy.Stop()
			return fmt.Errorf("failed to initialize Linux bridge: %w", err)
		}
		m.linuxBridge = bridge

		// Set up reverse bridge for exposed ports (inbound connections)
		if len(m.exposedPorts) > 0 {
			reverseBridge, err := NewReverseBridge(m.exposedPorts, m.debug)
			if err != nil {
				m.linuxBridge.Cleanup()
				m.httpProxy.Stop()
				m.socksProxy.Stop()
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		}
	}

	m.initialized = true
	m.logDebug("Sandbox manager initialized (HTTP proxy: %d, SOCKS proxy: %d)", m.httpPort, m.socksPort)
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
func (m *Manager) WrapCommand(command string) (string, error) {
	if !m.initialized {
		if err := m.Initialize(); err != nil {
			return "", err
		}
	}

	plat := platform.Detect()
	switch plat {
	case platform.MacOS:
		return WrapCommandMacOS(m.config, command, m.httpPort, m.socksPort, m.exposedPorts, m.debug)
	case platform.Linux:
		return WrapCommandLinux(m.config, command, m.linuxBridge, m.reverseBridge, m.debug)
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	if m.reverseBridge != nil {
		m.reverseBridge.Cleanup()
	}
	if m.linuxBridge != nil {
		m.linuxBridge.Cleanup()
	}
	if m.httpProxy != nil {
		m.httpProxy.Stop()
	}
	if m.socksProxy != nil {
		m.socksProxy.Stop()
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[fence] "+format+"\n", args...)
	}
}

// HTTPPort returns the HTTP proxy port.
func (m *Manager) HTTPPort() int {
	return m.httpPort
}

// SOCKSPort returns the SOCKS proxy port.
func (m *Manager) SOCKSPort() int {
	return m.socksPort
}
