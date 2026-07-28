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
)

type linuxBootstrapBridgeSpec struct {
	ListenNetwork string `json:"listenNetwork"`
	ListenAddress string `json:"listenAddress"`
	TargetNetwork string `json:"targetNetwork"`
	TargetAddress string `json:"targetAddress"`
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
		plan.Bridges = append(
			plan.Bridges,
			linuxBootstrapBridgeSpec{
				ListenNetwork: "tcp",
				ListenAddress: "127.0.0.1:3128",
				TargetNetwork: "unix",
				TargetAddress: bridge.HTTPSocketPath,
			},
			linuxBootstrapBridgeSpec{
				ListenNetwork: "tcp",
				ListenAddress: "127.0.0.1:1080",
				TargetNetwork: "unix",
				TargetAddress: bridge.SOCKSSocketPath,
			},
		)
		for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			plan.Runtime.Set[key] = "http://127.0.0.1:3128"
		}
		for _, key := range []string{"ALL_PROXY", "all_proxy"} {
			plan.Runtime.Set[key] = "socks5h://127.0.0.1:1080"
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
		if len(localOutboundBridge.Ports) != len(localOutboundBridge.SocketPaths) {
			return linuxBootstrapPlan{}, fmt.Errorf(
				"local-outbound bridge has %d ports and %d socket paths",
				len(localOutboundBridge.Ports),
				len(localOutboundBridge.SocketPaths),
			)
		}
		for i, port := range localOutboundBridge.Ports {
			plan.Bridges = append(plan.Bridges, linuxBootstrapBridgeSpec{
				ListenNetwork: "tcp",
				ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
				TargetNetwork: "unix",
				TargetAddress: localOutboundBridge.SocketPaths[i],
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
	if err := plan.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("encode Linux bootstrap plan: %w", err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return nil, fmt.Errorf(
			"Linux bootstrap plan is %d bytes; maximum is %d",
			len(data),
			linuxBootstrapPlanMaxBytes,
		)
	}
	return data, nil
}

func encodeLinuxBootstrapBridgePlan(plan linuxBootstrapBridgePlan) ([]byte, error) {
	if err := plan.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("encode Linux bootstrap bridge plan: %w", err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return nil, fmt.Errorf(
			"Linux bootstrap bridge plan is %d bytes; maximum is %d",
			len(data),
			linuxBootstrapPlanMaxBytes,
		)
	}
	return data, nil
}

func decodeLinuxBootstrapPlan(r io.Reader) (linuxBootstrapPlan, error) {
	limited := io.LimitReader(r, linuxBootstrapPlanMaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return linuxBootstrapPlan{}, fmt.Errorf("read Linux bootstrap plan: %w", err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return linuxBootstrapPlan{}, fmt.Errorf(
			"Linux bootstrap plan exceeds %d bytes",
			linuxBootstrapPlanMaxBytes,
		)
	}

	var plan linuxBootstrapPlan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return linuxBootstrapPlan{}, fmt.Errorf("decode Linux bootstrap plan: %w", err)
	}
	if err := ensureLinuxBootstrapPlanEOF(decoder); err != nil {
		return linuxBootstrapPlan{}, err
	}
	if err := plan.validate(); err != nil {
		return linuxBootstrapPlan{}, err
	}
	return plan, nil
}

func decodeLinuxBootstrapBridgePlan(r io.Reader) (linuxBootstrapBridgePlan, error) {
	limited := io.LimitReader(r, linuxBootstrapPlanMaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return linuxBootstrapBridgePlan{}, fmt.Errorf("read Linux bootstrap bridge plan: %w", err)
	}
	if len(data) > linuxBootstrapPlanMaxBytes {
		return linuxBootstrapBridgePlan{}, fmt.Errorf(
			"Linux bootstrap bridge plan exceeds %d bytes",
			linuxBootstrapPlanMaxBytes,
		)
	}

	var plan linuxBootstrapBridgePlan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return linuxBootstrapBridgePlan{}, fmt.Errorf("decode Linux bootstrap bridge plan: %w", err)
	}
	if err := ensureLinuxBootstrapPlanEOF(decoder); err != nil {
		return linuxBootstrapBridgePlan{}, err
	}
	if err := plan.validate(); err != nil {
		return linuxBootstrapBridgePlan{}, err
	}
	return plan, nil
}

func ensureLinuxBootstrapPlanEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing Linux bootstrap plan data: %w", err)
	}
	return fmt.Errorf("Linux bootstrap plan contains trailing JSON")
}

func (plan linuxBootstrapPlan) validate() error {
	if plan.Version != linuxBootstrapPlanVersion {
		return fmt.Errorf(
			"unsupported Linux bootstrap plan version %d (expected %d)",
			plan.Version,
			linuxBootstrapPlanVersion,
		)
	}
	if len(plan.Bridges) > linuxBootstrapPlanMaxBridges {
		return fmt.Errorf(
			"Linux bootstrap plan contains %d bridges; maximum is %d",
			len(plan.Bridges),
			linuxBootstrapPlanMaxBridges,
		)
	}
	for i, bridge := range plan.Bridges {
		if err := bridge.validate(); err != nil {
			return fmt.Errorf("invalid Linux bootstrap bridge %d: %w", i, err)
		}
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
	if len(plan.Bridges) > linuxBootstrapPlanMaxBridges {
		return fmt.Errorf(
			"Linux bootstrap bridge plan contains %d bridges; maximum is %d",
			len(plan.Bridges),
			linuxBootstrapPlanMaxBridges,
		)
	}
	for i, bridge := range plan.Bridges {
		if err := bridge.validate(); err != nil {
			return fmt.Errorf("invalid Linux bootstrap bridge %d: %w", i, err)
		}
	}
	for _, path := range plan.CleanupPaths {
		cleaned := filepath.Clean(path)
		if filepath.Dir(cleaned) != "/tmp" || !strings.HasPrefix(filepath.Base(cleaned), "fence-runtime-") {
			return fmt.Errorf("invalid Linux bootstrap cleanup path %q", path)
		}
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
