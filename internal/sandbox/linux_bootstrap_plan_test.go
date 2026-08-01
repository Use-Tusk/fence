//go:build linux

package sandbox

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/fencesandbox/fence/internal/config"
)

func TestLinuxBootstrapPlanRoundTrip(t *testing.T) {
	plan := linuxBootstrapPlan{
		Version: linuxBootstrapPlanVersion,
		Bridges: []linuxBootstrapBridgeSpec{
			{
				ListenNetwork: "tcp",
				ListenAddress: "127.0.0.1:3128",
				TargetNetwork: "unix",
				TargetAddress: "/tmp/fence-http.sock",
			},
			{
				ListenNetwork: "unix",
				ListenAddress: "/tmp/fence-reverse.sock",
				TargetNetwork: "tcp",
				TargetAddress: "127.0.0.1:3000",
			},
		},
		Runtime: linuxBootstrapRuntimeEnvPlan{
			Set: map[string]string{
				"FENCE_SANDBOX": "1",
				"HTTP_PROXY":    "http://127.0.0.1:3128",
			},
			RepairTMPDIR:        true,
			RepairXDGRuntimeDir: true,
		},
		Exec: linuxBootstrapExecPlan{
			Argv: []string{linuxBootstrapShellPath, "-c", "echo ok"},
		},
		Debug: true,
	}

	encoded, err := encodeLinuxBootstrapPlan(plan)
	if err != nil {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v", err)
	}
	decoded, err := decodeLinuxBootstrapPlan(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("decodeLinuxBootstrapPlan() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, plan) {
		t.Fatalf("decoded plan = %#v, want %#v", decoded, plan)
	}
}

func TestLinuxBootstrapPlanRejectsUnsupportedVersion(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Version++

	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "unsupported Linux bootstrap plan version") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want unsupported version", err)
	}
}

func TestLinuxBootstrapBridgePlanRoundTrip(t *testing.T) {
	plan := linuxBootstrapBridgePlan{
		Version: linuxBootstrapPlanVersion,
		Bridges: []linuxBootstrapBridgeSpec{{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:3128",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-http.sock",
		}},
		Debug: true,
	}

	encoded, err := encodeLinuxBootstrapBridgePlan(plan)
	if err != nil {
		t.Fatalf("encodeLinuxBootstrapBridgePlan() error = %v", err)
	}
	decoded, err := decodeLinuxBootstrapBridgePlan(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("decodeLinuxBootstrapBridgePlan() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, plan) {
		t.Fatalf("decoded bridge plan = %#v, want %#v", decoded, plan)
	}
}

func TestLinuxBootstrapBridgePlanAllowsCleanupOnly(t *testing.T) {
	plan := linuxBootstrapBridgePlan{
		Version:      linuxBootstrapPlanVersion,
		CleanupPaths: []string{"/tmp/fence-runtime-1000-example"},
	}
	if _, err := encodeLinuxBootstrapBridgePlan(plan); err != nil {
		t.Fatalf("encodeLinuxBootstrapBridgePlan() error = %v", err)
	}
}

func TestLinuxBootstrapBridgePlanRejectsUnsafeCleanupPath(t *testing.T) {
	plan := linuxBootstrapBridgePlan{
		Version:      linuxBootstrapPlanVersion,
		CleanupPaths: []string{"/tmp/not-owned-by-fence"},
	}
	_, err := encodeLinuxBootstrapBridgePlan(plan)
	if err == nil || !strings.Contains(err.Error(), "invalid Linux bootstrap cleanup path") {
		t.Fatalf("encodeLinuxBootstrapBridgePlan() error = %v, want cleanup validation", err)
	}
}

func TestLinuxBootstrapPlanRejectsUnknownFields(t *testing.T) {
	raw := `{
		"version": 1,
		"runtime": {},
		"exec": {"argv": ["/bin/sh", "-c", "true"]},
		"unknown": true
	}`

	_, err := decodeLinuxBootstrapPlan(strings.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), `unknown field "unknown"`) {
		t.Fatalf("decodeLinuxBootstrapPlan() error = %v, want unknown field", err)
	}
}

func TestLinuxBootstrapPlanRejectsTrailingJSON(t *testing.T) {
	raw := `{"version":1,"runtime":{},"exec":{"argv":["/bin/sh","-c","true"]}} {}`

	_, err := decodeLinuxBootstrapPlan(strings.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("decodeLinuxBootstrapPlan() error = %v, want trailing JSON", err)
	}
}

func TestLinuxBootstrapPlanRejectsNonLoopbackTCP(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Bridges = []linuxBootstrapBridgeSpec{
		{
			ListenNetwork: "tcp",
			ListenAddress: "0.0.0.0:3128",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-http.sock",
		},
	}

	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "must use a loopback IP") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want loopback validation", err)
	}
}

func TestLinuxBootstrapPlanRejectsRelativeUnixPath(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Bridges = []linuxBootstrapBridgeSpec{
		{
			ListenNetwork: "unix",
			ListenAddress: "relative.sock",
			TargetNetwork: "tcp",
			TargetAddress: "127.0.0.1:3000",
		},
	}

	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want absolute path validation", err)
	}
}

func TestLinuxBootstrapPlanRejectsInvalidEnvironmentKey(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Runtime.Set = map[string]string{"INVALID=KEY": "value"}

	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "invalid Linux bootstrap environment key") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want environment key validation", err)
	}
}

func TestLinuxBootstrapPlanRejectsOversizedPlan(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Exec.Argv = append(plan.Exec.Argv, strings.Repeat("x", linuxBootstrapPlanMaxBytes))

	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "maximum is") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want size validation", err)
	}
}

func TestBuildLinuxBootstrapPlanIncludesEveryBridgeDirection(t *testing.T) {
	plan, err := buildLinuxBootstrapPlan(
		&config.Config{},
		"echo ok",
		&LinuxBridge{
			HTTPSocketPath:  "/tmp/fence-http.sock",
			SOCKSSocketPath: "/tmp/fence-socks.sock",
		},
		&ReverseBridge{
			Ports:       []int{3000},
			SocketPaths: []string{"/tmp/fence-reverse.sock"},
		},
		&LocalOutboundBridge{
			Ports:         []int{5432},
			SocketPaths:   []string{"/tmp/fence-local-v4.sock"},
			SocketPathsV6: []string{"/tmp/fence-local-v6.sock"},
		},
		linuxBootstrapExecutables{
			Shell: linuxBootstrapShellPath,
			Fence: linuxBootstrapFencePath,
		},
		"-c",
		false,
		false,
		true,
	)
	if err != nil {
		t.Fatalf("buildLinuxBootstrapPlan() error = %v", err)
	}

	wantBridges := []linuxBootstrapBridgeSpec{
		{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:3128",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-http.sock",
		},
		{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:1080",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-socks.sock",
		},
		{
			ListenNetwork: "unix",
			ListenAddress: "/tmp/fence-reverse.sock",
			TargetNetwork: "tcp",
			TargetAddress: "127.0.0.1:3000",
		},
		{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:5432",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-local-v4.sock",
		},
		{
			ListenNetwork: "tcp",
			ListenAddress: "[::1]:5432",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/fence-local-v6.sock",
			Optional:      true,
		},
	}
	if !reflect.DeepEqual(plan.Bridges, wantBridges) {
		t.Fatalf("bridges = %#v, want %#v", plan.Bridges, wantBridges)
	}
	if got := plan.Runtime.Set["FENCE_SANDBOX"]; got != "1" {
		t.Fatalf("FENCE_SANDBOX = %q, want 1", got)
	}
	if got := plan.Runtime.Set["NO_PROXY"]; got != "localhost,127.0.0.1,::1" {
		t.Fatalf("NO_PROXY = %q", got)
	}
	if got := plan.Exec.Argv; !reflect.DeepEqual(got, []string{linuxBootstrapShellPath, "-c", "echo ok"}) {
		t.Fatalf("exec argv = %#v", got)
	}
}

func TestBuildLinuxBootstrapPlanUsesDirectProxyPortsWithoutNetworkNamespace(t *testing.T) {
	plan, err := buildLinuxBootstrapPlan(
		&config.Config{},
		"echo ok",
		newDirectLinuxBridge(41001, 41002, false),
		nil,
		nil,
		linuxBootstrapExecutables{
			Shell: linuxBootstrapShellPath,
			Fence: linuxBootstrapFencePath,
		},
		"-c",
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("buildLinuxBootstrapPlan() error = %v", err)
	}
	if len(plan.Bridges) != 0 {
		t.Fatalf("direct proxy plan unexpectedly contains bridge listeners: %#v", plan.Bridges)
	}
	if got := plan.Runtime.Set["HTTP_PROXY"]; got != "http://127.0.0.1:41001" {
		t.Fatalf("HTTP_PROXY = %q, want direct host proxy port", got)
	}
	if got := plan.Runtime.Set["ALL_PROXY"]; got != "socks5h://127.0.0.1:41002" {
		t.Fatalf("ALL_PROXY = %q, want direct host proxy port", got)
	}
}

func TestBuildLinuxBootstrapPlanRejectsPartialProxySocketBridge(t *testing.T) {
	_, err := buildLinuxBootstrapPlan(
		&config.Config{},
		"echo ok",
		&LinuxBridge{HTTPSocketPath: "/tmp/fence-http.sock"},
		nil,
		nil,
		linuxBootstrapExecutables{
			Shell: linuxBootstrapShellPath,
			Fence: linuxBootstrapFencePath,
		},
		"-c",
		false,
		false,
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "both HTTP and SOCKS socket paths") {
		t.Fatalf("buildLinuxBootstrapPlan() error = %v, want partial-bridge error", err)
	}
}

func TestBuildLinuxBootstrapPlanComposesArgvAndLandlockShims(t *testing.T) {
	plan, err := buildLinuxBootstrapPlan(
		&config.Config{},
		"echo ok",
		nil,
		nil,
		nil,
		linuxBootstrapExecutables{
			Shell: linuxBootstrapShellPath,
			Fence: linuxBootstrapFencePath,
		},
		"-c",
		true,
		true,
		true,
	)
	if err != nil {
		t.Fatalf("buildLinuxBootstrapPlan() error = %v", err)
	}

	want := []string{
		linuxBootstrapFencePath,
		linuxArgvExecShimMode,
		"--debug",
		"--",
		linuxBootstrapFencePath,
		"--landlock-apply",
		"--debug",
		"--",
		linuxBootstrapShellPath,
		"-c",
		"echo ok",
	}
	if !reflect.DeepEqual(plan.Exec.Argv, want) {
		t.Fatalf("exec argv = %#v, want %#v", plan.Exec.Argv, want)
	}
	if plan.Runtime.Set["FENCE_CONFIG_JSON"] == "" {
		t.Fatal("expected serialized Landlock config in runtime environment")
	}
}

func TestBuildLinuxBootstrapPlanRejectsReservedLocalOutboundPorts(t *testing.T) {
	for _, port := range []int{linuxBootstrapHTTPProxyPort, linuxBootstrapSOCKSProxyPort} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			_, err := buildLinuxBootstrapPlan(
				&config.Config{},
				"echo ok",
				&LinuxBridge{
					HTTPSocketPath:  "/tmp/fence-http.sock",
					SOCKSSocketPath: "/tmp/fence-socks.sock",
				},
				nil,
				&LocalOutboundBridge{
					Ports:         []int{port},
					SocketPaths:   []string{"/tmp/fence-local-v4.sock"},
					SocketPathsV6: []string{"/tmp/fence-local-v6.sock"},
				},
				linuxBootstrapExecutables{
					Shell: linuxBootstrapShellPath,
					Fence: linuxBootstrapFencePath,
				},
				"-c",
				false,
				false,
				false,
			)
			if err == nil || !strings.Contains(err.Error(), "reserved in-sandbox proxy port") {
				t.Fatalf("buildLinuxBootstrapPlan() error = %v, want reserved-port error", err)
			}
		})
	}
}

func TestLinuxBootstrapPlanRejectsDuplicateListeners(t *testing.T) {
	plan := validLinuxBootstrapPlan()
	plan.Bridges = []linuxBootstrapBridgeSpec{
		{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:8080",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/first.sock",
		},
		{
			ListenNetwork: "tcp",
			ListenAddress: "127.0.0.1:8080",
			TargetNetwork: "unix",
			TargetAddress: "/tmp/second.sock",
		},
	}
	_, err := encodeLinuxBootstrapPlan(plan)
	if err == nil || !strings.Contains(err.Error(), "both listen on tcp 127.0.0.1:8080") {
		t.Fatalf("encodeLinuxBootstrapPlan() error = %v, want duplicate-listener error", err)
	}
}

func validLinuxBootstrapPlan() linuxBootstrapPlan {
	return linuxBootstrapPlan{
		Version: linuxBootstrapPlanVersion,
		Runtime: linuxBootstrapRuntimeEnvPlan{
			Set: map[string]string{"FENCE_SANDBOX": "1"},
		},
		Exec: linuxBootstrapExecPlan{
			Argv: []string{linuxBootstrapShellPath, "-c", "true"},
		},
	}
}
