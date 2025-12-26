// Package main implements the fence CLI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/spf13/cobra"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	debug         bool
	monitor       bool
	settingsPath  string
	cmdString     string
	exposePorts   []string
	exitCode      int
	showVersion   bool
	linuxFeatures bool
)

func main() {
	// Check for internal --landlock-apply mode (used inside sandbox)
	// This must be checked before cobra to avoid flag conflicts
	if len(os.Args) >= 2 && os.Args[1] == "--landlock-apply" {
		runLandlockWrapper()
		return
	}

	rootCmd := &cobra.Command{
		Use:   "fence [flags] -- [command...]",
		Short: "Run commands in a sandbox with network and filesystem restrictions",
		Long: `fence is a command-line tool that runs commands in a sandboxed environment
with network and filesystem restrictions.

By default, all network access is blocked. Configure allowed domains in
~/.fence.json or pass a settings file with --settings.

Examples:
  fence curl https://example.com          # Will be blocked (no domains allowed)
  fence -- curl -s https://example.com    # Use -- to separate fence flags from command
  fence -c "echo hello && ls"             # Run with shell expansion
  fence --settings config.json npm install
  fence -p 3000 -c "npm run dev"          # Expose port 3000 for inbound connections
  fence -p 3000 -p 8080 -c "npm start"    # Expose multiple ports

Configuration file format (~/.fence.json):
{
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  }
}`,
		RunE:          runCommand,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
	}

	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.Flags().BoolVarP(&monitor, "monitor", "m", false, "Monitor and log sandbox violations (macOS: log stream, all: proxy denials)")
	rootCmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: ~/.fence.json)")
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
	rootCmd.Flags().BoolVar(&linuxFeatures, "linux-features", false, "Show available Linux security features and exit")

	rootCmd.Flags().SetInterspersed(true)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("fence - lightweight, container-free sandbox for running untrusted commands\n")
		fmt.Printf("  Version: %s\n", version)
		fmt.Printf("  Built:   %s\n", buildTime)
		fmt.Printf("  Commit:  %s\n", gitCommit)
		return nil
	}

	if linuxFeatures {
		sandbox.PrintLinuxFeatures()
		return nil
	}

	var command string
	switch {
	case cmdString != "":
		command = cmdString
	case len(args) > 0:
		command = strings.Join(args, " ")
	default:
		return fmt.Errorf("no command specified. Use -c <command> or provide command arguments")
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence] Command: %s\n", command)
	}

	var ports []int
	for _, p := range exposePorts {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, port)
	}

	if debug && len(ports) > 0 {
		fmt.Fprintf(os.Stderr, "[fence] Exposing ports: %v\n", ports)
	}

	configPath := settingsPath
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg == nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence] No config found at %s, using default (block all network)\n", configPath)
		}
		cfg = config.Default()
	}

	manager := sandbox.NewManager(cfg, debug, monitor)
	manager.SetExposedPorts(ports)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize sandbox: %w", err)
	}

	var logMonitor *sandbox.LogMonitor
	if monitor {
		logMonitor = sandbox.NewLogMonitor(sandbox.GetSessionSuffix())
		if logMonitor != nil {
			if err := logMonitor.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[fence] Warning: failed to start log monitor: %v\n", err)
			} else {
				defer logMonitor.Stop()
			}
		}
	}

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence] Sandboxed command: %s\n", sandboxedCommand)
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand) //nolint:gosec // sandboxedCommand is constructed from user input - intentional
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the command (non-blocking) so we can get the PID
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Start Linux monitors (eBPF tracing for filesystem violations)
	var linuxMonitors *sandbox.LinuxMonitors
	if monitor && execCmd.Process != nil {
		linuxMonitors, _ = sandbox.StartLinuxMonitor(execCmd.Process.Pid, sandbox.LinuxSandboxOptions{
			Monitor: true,
			Debug:   debug,
			UseEBPF: true,
		})
		if linuxMonitors != nil {
			defer linuxMonitors.Stop()
		}
	}

	// Note: Landlock is NOT applied here because:
	// 1. The sandboxed command is already running (Landlock only affects future children)
	// 2. Proper Landlock integration requires applying restrictions inside the sandbox
	// For now, filesystem isolation relies on bwrap mount namespaces.
	// Landlock code exists for future integration (e.g., via a wrapper binary).

	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
		// Give child time to exit, then cleanup will happen via defer
	}()

	// Wait for command to finish
	if err := execCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Set exit code but don't os.Exit() here - let deferred cleanup run
			exitCode = exitErr.ExitCode()
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// runLandlockWrapper runs in "wrapper mode" inside the sandbox.
// It applies Landlock restrictions and then execs the user command.
// Usage: fence --landlock-apply [--debug] -- <command...>
// Config is passed via FENCE_CONFIG_JSON environment variable.
func runLandlockWrapper() {
	// Parse arguments: --landlock-apply [--debug] -- <command...>
	args := os.Args[2:] // Skip "fence" and "--landlock-apply"

	var debugMode bool
	var cmdStart int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
		case "--":
			cmdStart = i + 1
			goto parseCommand
		default:
			// Assume rest is the command
			cmdStart = i
			goto parseCommand
		}
	}

parseCommand:
	if cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Error: no command specified\n")
		os.Exit(1)
	}

	command := args[cmdStart:]

	if debugMode {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Applying Landlock restrictions\n")
	}

	// Only apply Landlock on Linux
	if platform.Detect() == platform.Linux {
		// Load config from environment variable (passed by parent fence process)
		var cfg *config.Config
		if configJSON := os.Getenv("FENCE_CONFIG_JSON"); configJSON != "" {
			cfg = &config.Config{}
			if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
				if debugMode {
					fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Warning: failed to parse config: %v\n", err)
				}
				cfg = nil
			}
		}
		if cfg == nil {
			cfg = config.Default()
		}

		// Get current working directory for relative path resolution
		cwd, _ := os.Getwd()

		// Apply Landlock restrictions
		err := sandbox.ApplyLandlockFromConfig(cfg, cwd, nil, debugMode)
		if err != nil {
			if debugMode {
				fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Warning: Landlock not applied: %v\n", err)
			}
			// Continue without Landlock - bwrap still provides isolation
		} else if debugMode {
			fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Landlock restrictions applied\n")
		}
	}

	// Find the executable
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Error: command not found: %s\n", command[0])
		os.Exit(127)
	}

	if debugMode {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Exec: %s %v\n", execPath, command[1:])
	}

	// Exec the command (replaces this process)
	err = syscall.Exec(execPath, command, os.Environ()) //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Exec failed: %v\n", err)
		os.Exit(1)
	}
}
