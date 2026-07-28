//go:build linux

package sandbox

import (
	"fmt"

	"github.com/fencesandbox/fence/internal/fencelog"
)

func (m *Manager) initializePlatformNetworking() error {
	features := DetectLinuxFeatures()
	useNetworkNamespace := features.CanUnshareNet && !hasWildcardAllowedDomain(m.config)
	if useNetworkNamespace {
		bridge, err := NewLinuxBridge(m.httpPort, m.socksPort, m.debug)
		if err != nil {
			_ = m.httpProxy.Stop()
			_ = m.socksProxy.Stop()
			return fmt.Errorf("failed to initialize Linux bridge: %w", err)
		}
		m.linuxBridge = bridge
	} else {
		m.linuxBridge = newDirectLinuxBridge(m.httpPort, m.socksPort, m.debug)
		if m.debug {
			m.logDebug("Using direct host proxy ports (network namespace not active)")
		}
	}

	// Set up reverse bridge for exposed ports (inbound connections).
	// Only needed when:
	//   (a) a network namespace is available (otherwise host & sandbox
	//       share the netns and external traffic reaches listeners directly), and
	//   (b) the service binds its port INSIDE the sandbox. For
	//       ServiceBindsOnHost (docker, podman, ...), the port is bound by
	//       an external daemon outside the netns; a reverse bridge on the
	//       same port would collide with the daemon's bind.
	exposures := m.service.resolvedExposures()
	switch {
	case len(exposures) == 0:
		// nothing to do
	case m.service.ExecutionModel == ServiceBindsOnHost:
		if m.debug {
			m.logDebug("Skipping reverse bridge (ServiceBindsOnHost: external daemon binds ports %v outside sandbox netns)", m.service.resolvedPorts())
		}
	case !features.CanUnshareNet:
		if m.debug {
			m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
		}
	default:
		reverseBridge, err := NewReverseBridge(exposures, m.debug)
		if err != nil {
			m.linuxBridge.Cleanup()
			_ = m.httpProxy.Stop()
			_ = m.socksProxy.Stop()
			return fmt.Errorf("failed to initialize reverse bridge: %w", err)
		}
		m.reverseBridge = reverseBridge
	}

	// Set up the localhost-outbound bridge when the user opted into
	// host-loopback access. The bridge is only meaningful when we also
	// unshare the network namespace (otherwise sandbox 127.0.0.1 already
	// is the host's 127.0.0.1 and no forwarding is needed). Wildcard
	// relaxed mode drops --unshare-net too, so skip there.
	if m.config != nil && m.config.Network.EffectiveAllowLocalOutbound() && features.CanUnshareNet && !hasWildcardAllowedDomain(m.config) {
		ports := m.config.Network.AllowLocalOutboundPorts
		if len(ports) > 0 {
			loBridge, err := NewLocalOutboundBridge(ports, m.debug)
			if err != nil {
				if m.reverseBridge != nil {
					m.reverseBridge.Cleanup()
				}
				m.linuxBridge.Cleanup()
				_ = m.httpProxy.Stop()
				_ = m.socksProxy.Stop()
				return fmt.Errorf("failed to initialize localhost-outbound bridge: %w", err)
			}
			m.localOutboundBridge = loBridge
		} else {
			// Surface the Linux-specific limitation once at startup so
			// users do not silently get the pre-fix broken behavior.
			fencelog.Printf(
				"[fence] network.allowLocalOutbound=true on Linux requires network.allowLocalOutboundPorts to list the host loopback ports to bridge (e.g. [5432, 6379]). Without it, sandbox connections to 127.0.0.1 stay isolated inside the sandbox network namespace.\n",
			)
		}
	}

	return nil
}
