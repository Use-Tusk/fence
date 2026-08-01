//go:build linux

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fencesandbox/fence/internal/config"
)

const (
	linuxBootstrapPlanVersion    = 1
	linuxBootstrapPlanMaxBytes   = 120 * 1024
	linuxBootstrapPlanMaxBridges = 1024
	linuxBootstrapHTTPProxyPort  = 3128
	linuxBootstrapSOCKSProxyPort = 1080
)

type linuxBootstrapBridgeSpec struct {
	ListenNetwork string `json:"listenNetwork"`
	ListenAddress string `json:"listenAddress"`
	TargetNetwork string `json:"targetNetwork"`
	TargetAddress string `json:"targetAddress"`
	Optional      bool   `json:"optional,omitempty"`
}

type linuxBootstrapRuntimeEnvPlan struct {
	Set                 map[string]string `json:"set,omitempty"`
	RepairTMPDIR        bool              `json:"repairTmpDir,omitempty"`
	RepairXDGRuntimeDir bool              `json:"repairXdgRuntimeDir,omitempty"`
}

type linuxBootstrapExecPlan struct {
	Argv []string `json:"argv"`
}

type linuxBootstrapPlan struct {
	Version int                          `json:"version"`
	Bridges []linuxBootstrapBridgeSpec   `json:"bridges,omitempty"`
	Runtime linuxBootstrapRuntimeEnvPlan `json:"runtime"`
	Exec    linuxBootstrapExecPlan       `json:"exec"`
	Debug   bool                         `json:"debug,omitempty"`
}

type linuxBootstrapBridgePlan struct {
	Version      int                        `json:"version"`
	Bridges      []linuxBootstrapBridgeSpec `json:"bridges,omitempty"`
	CleanupPaths []string                   `json:"cleanupPaths,omitempty"`
	Debug        bool                       `json:"debug,omitempty"`
}

func buildLinuxBootstrapPlan(
	cfg *config.Config,
	command string,
	bridge *LinuxBridge,
	reverseBridge *ReverseBridge,
	localOutboundBridge *LocalOutboundBridge,
	bootstrapExecs linuxBootstrapExecutables,
	shellFlag string,
	useLandlockWrapper bool,
	useArgvRuntimeExecPolicy bool,
	debug bool,
) (linuxBootstrapPlan, error) {
	plan := linuxBootstrapPlan{
		Version: linuxBootstrapPlanVersion,
		Runtime: linuxBootstrapRuntimeEnvPlan{
			Set: map[string]string{
				"FENCE_SANDBOX": "1",
			},
			RepairTMPDIR:        true,
			RepairXDGRuntimeDir: true,
		},
		Debug: debug,
	}

	if bridge != nil {
		httpPort := linuxBootstrapHTTPProxyPort
		socksPort := linuxBootstrapSOCKSProxyPort
		hasHTTPSocket := bridge.HTTPSocketPath != ""
		hasSOCKSSocket := bridge.SOCKSSocketPath != ""
		if hasHTTPSocket != hasSOCKSSocket {
			return linuxBootstrapPlan{}, fmt.Errorf("Linux proxy bridge must provide both HTTP and SOCKS socket paths")
		}
		if hasHTTPSocket {
			plan.Bridges = append(
				plan.Bridges,
				linuxBootstrapBridgeSpec{
					ListenNetwork: "tcp",
					ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
					TargetNetwork: "unix",
					TargetAddress: bridge.HTTPSocketPath,
				},
				linuxBootstrapBridgeSpec{
					ListenNetwork: "tcp",
					ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
					TargetNetwork: "unix",
					TargetAddress: bridge.SOCKSSocketPath,
				},
			)
		} else {
			if bridge.HTTPProxyPort < 1 || bridge.HTTPProxyPort > 65535 ||
				bridge.SOCKSProxyPort < 1 || bridge.SOCKSProxyPort > 65535 {
				return linuxBootstrapPlan{}, fmt.Errorf(
					"direct Linux proxy ports must be in range 1-65535 (HTTP=%d, SOCKS=%d)",
					bridge.HTTPProxyPort,
					bridge.SOCKSProxyPort,
				)
			}
			httpPort = bridge.HTTPProxyPort
			socksPort = bridge.SOCKSProxyPort
		}
		for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			plan.Runtime.Set[key] = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		}
		for _, key := range []string{"ALL_PROXY", "all_proxy"} {
			plan.Runtime.Set[key] = fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)
		}
		plan.Runtime.Set["NO_PROXY"] = "localhost,127.0.0.1,::1"
		plan.Runtime.Set["no_proxy"] = "localhost,127.0.0.1,::1"
	}

	if reverseBridge != nil {
		if len(reverseBridge.Ports) != len(reverseBridge.SocketPaths) {
			return linuxBootstrapPlan{}, fmt.Errorf(
				"reverse bridge has %d ports and %d socket paths",
				len(reverseBridge.Ports),
				len(reverseBridge.SocketPaths),
			)
		}
		for i, port := range reverseBridge.Ports {
			plan.Bridges = append(plan.Bridges, linuxBootstrapBridgeSpec{
				ListenNetwork: "unix",
				ListenAddress: reverseBridge.SocketPaths[i],
				TargetNetwork: "tcp",
				TargetAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			})
		}
	}

	if localOutboundBridge != nil {
		if len(localOutboundBridge.Ports) != len(localOutboundBridge.SocketPaths) ||
			len(localOutboundBridge.Ports) != len(localOutboundBridge.SocketPathsV6) {
			return linuxBootstrapPlan{}, fmt.Errorf(
				"local-outbound bridge has %d ports, %d IPv4 socket paths, and %d IPv6 socket paths",
				len(localOutboundBridge.Ports),
				len(localOutboundBridge.SocketPaths),
				len(localOutboundBridge.SocketPathsV6),
			)
		}
		for i, port := range localOutboundBridge.Ports {
			if port == linuxBootstrapHTTPProxyPort || port == linuxBootstrapSOCKSProxyPort {
				return linuxBootstrapPlan{}, fmt.Errorf(
					"network.allowLocalOutboundPorts entry %d conflicts with a reserved in-sandbox proxy port",
					port,
				)
			}
			plan.Bridges = append(plan.Bridges, linuxBootstrapBridgeSpec{
				ListenNetwork: "tcp",
				ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
				TargetNetwork: "unix",
				TargetAddress: localOutboundBridge.SocketPaths[i],
			})
			plan.Bridges = append(plan.Bridges, linuxBootstrapBridgeSpec{
				ListenNetwork: "tcp",
				ListenAddress: net.JoinHostPort("::1", strconv.Itoa(port)),
				TargetNetwork: "unix",
				TargetAddress: localOutboundBridge.SocketPathsV6[i],
				Optional:      true,
			})
		}
	}

	execArgv := []string{bootstrapExecs.Shell, shellFlag, command}
	if useLandlockWrapper {
		if cfg == nil {
			cfg = config.Default()
		}
		configJSON, err := json.Marshal(cfg)
		if err != nil {
			return linuxBootstrapPlan{}, fmt.Errorf("encode Landlock config for Linux bootstrap: %w", err)
		}
		plan.Runtime.Set["FENCE_CONFIG_JSON"] = string(configJSON)

		landlockArgv := []string{bootstrapExecs.Fence, "--landlock-apply"}
		if debug {
			landlockArgv = append(landlockArgv, "--debug")
		}
		landlockArgv = append(landlockArgv, "--")
		execArgv = append(landlockArgv, execArgv...)
	}
	if useArgvRuntimeExecPolicy {
		argvShim := []string{bootstrapExecs.Fence, linuxArgvExecShimMode}
		if debug {
			argvShim = append(argvShim, "--debug")
		}
		argvShim = append(argvShim, "--")
		execArgv = append(argvShim, execArgv...)
	}
	plan.Exec.Argv = execArgv

	if err := plan.validate(); err != nil {
		return linuxBootstrapPlan{}, err
	}
	return plan, nil
}

func encodeLinuxBootstrapPlan(plan linuxBootstrapPlan) ([]byte, error) {
	return encodeLinuxBootstrapJSON(plan, "Linux bootstrap plan")
}

func encodeLinuxBootstrapBridgePlan(plan linuxBootstrapBridgePlan) ([]byte, error) {
	return encodeLinuxBootstrapJSON(plan, "Linux bootstrap bridge plan")
}

func decodeLinuxBootstrapPlan(r io.Reader) (linuxBootstrapPlan, error) {
	return decodeLinuxBootstrapJSON[linuxBootstrapPlan](r, "Linux bootstrap plan")
}

func decodeLinuxBootstrapBridgePlan(r io.Reader) (linuxBootstrapBridgePlan, error) {
	return decodeLinuxBootstrapJSON[linuxBootstrapBridgePlan](r, "Linux bootstrap bridge plan")
}

type linuxBootstrapJSONPlan interface {
	validate() error
}

func encodeLinuxBootstrapJSON[T linuxBootstrapJSONPlan](plan T, label string) ([]byte, error) {
	if err := plan.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", label, err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return nil, fmt.Errorf(
			"%s is %d bytes; maximum is %d",
			label,
			len(data),
			linuxBootstrapPlanMaxBytes,
		)
	}
	return data, nil
}

func decodeLinuxBootstrapJSON[T linuxBootstrapJSONPlan](r io.Reader, label string) (T, error) {
	var plan T
	limited := io.LimitReader(r, linuxBootstrapPlanMaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return plan, fmt.Errorf("read %s: %w", label, err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return plan, fmt.Errorf(
			"%s exceeds %d bytes",
			label,
			linuxBootstrapPlanMaxBytes,
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return plan, fmt.Errorf("decode %s: %w", label, err)
	}
	if err := ensureLinuxBootstrapPlanEOF(decoder, label); err != nil {
		return plan, err
	}
	if err := plan.validate(); err != nil {
		return plan, err
	}
	return plan, nil
}

func ensureLinuxBootstrapPlanEOF(decoder *json.Decoder, label string) error {
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing %s data: %w", label, err)
	}
	return fmt.Errorf("%s contains trailing JSON", label)
}

func (plan linuxBootstrapPlan) validate() error {
	if plan.Version != linuxBootstrapPlanVersion {
		return fmt.Errorf(
			"unsupported Linux bootstrap plan version %d (expected %d)",
			plan.Version,
			linuxBootstrapPlanVersion,
		)
	}
	if err := validateLinuxBootstrapBridgeSpecs(plan.Bridges, "Linux bootstrap plan"); err != nil {
		return err
	}
	for key, value := range plan.Runtime.Set {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return fmt.Errorf("invalid Linux bootstrap environment key %q", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("Linux bootstrap environment value for %q contains NUL", key)
		}
	}
	if len(plan.Exec.Argv) == 0 || strings.TrimSpace(plan.Exec.Argv[0]) == "" {
		return fmt.Errorf("Linux bootstrap plan has no executable")
	}
	for i, arg := range plan.Exec.Argv {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("Linux bootstrap argv[%d] contains NUL", i)
		}
	}
	return nil
}

func (plan linuxBootstrapBridgePlan) validate() error {
	if plan.Version != linuxBootstrapPlanVersion {
		return fmt.Errorf(
			"unsupported Linux bootstrap bridge plan version %d (expected %d)",
			plan.Version,
			linuxBootstrapPlanVersion,
		)
	}
	if len(plan.Bridges) == 0 && len(plan.CleanupPaths) == 0 {
		return fmt.Errorf("Linux bootstrap bridge plan contains no work")
	}
	if err := validateLinuxBootstrapBridgeSpecs(plan.Bridges, "Linux bootstrap bridge plan"); err != nil {
		return err
	}
	for _, path := range plan.CleanupPaths {
		cleaned := filepath.Clean(path)
		if filepath.Dir(cleaned) != "/tmp" || !strings.HasPrefix(filepath.Base(cleaned), "fence-runtime-") {
			return fmt.Errorf("invalid Linux bootstrap cleanup path %q", path)
		}
	}
	return nil
}

func validateLinuxBootstrapBridgeSpecs(bridges []linuxBootstrapBridgeSpec, label string) error {
	if len(bridges) > linuxBootstrapPlanMaxBridges {
		return fmt.Errorf(
			"%s contains %d bridges; maximum is %d",
			label,
			len(bridges),
			linuxBootstrapPlanMaxBridges,
		)
	}
	listeners := make(map[string]int, len(bridges))
	for i, bridge := range bridges {
		if err := bridge.validate(); err != nil {
			return fmt.Errorf("invalid Linux bootstrap bridge %d: %w", i, err)
		}
		key := bridge.ListenNetwork + "\x00" + bridge.ListenAddress
		if previous, exists := listeners[key]; exists {
			return fmt.Errorf(
				"%s bridges %d and %d both listen on %s %s",
				label,
				previous,
				i,
				bridge.ListenNetwork,
				bridge.ListenAddress,
			)
		}
		listeners[key] = i
	}
	return nil
}

func (bridge linuxBootstrapBridgeSpec) validate() error {
	if err := validateLinuxBootstrapEndpoint(bridge.ListenNetwork, bridge.ListenAddress, true); err != nil {
		return fmt.Errorf("listen endpoint: %w", err)
	}
	if err := validateLinuxBootstrapEndpoint(bridge.TargetNetwork, bridge.TargetAddress, false); err != nil {
		return fmt.Errorf("target endpoint: %w", err)
	}
	return nil
}

func validateLinuxBootstrapEndpoint(network string, address string, listener bool) error {
	switch network {
	case "tcp":
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid TCP address %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("TCP address %q must use a loopback IP", address)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("TCP address %q must use a fixed non-zero port", address)
		}
	case "unix":
		if !filepath.IsAbs(address) {
			return fmt.Errorf("Unix address %q must be absolute", address)
		}
		if strings.ContainsRune(address, '\x00') {
			return fmt.Errorf("Unix address contains NUL")
		}
	default:
		role := "target"
		if listener {
			role = "listener"
		}
		return fmt.Errorf("unsupported %s network %q", role, network)
	}
	return nil
}
