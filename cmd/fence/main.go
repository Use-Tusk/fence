// Package main implements the fence CLI.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/spf13/cobra"
)

var (
	debug        bool
	settingsPath string
	cmdString    string
	exposePorts  []string
	exitCode     int
)

func main() {
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
	rootCmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: ~/.fence.json)")
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")

	rootCmd.Flags().SetInterspersed(true)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
	var command string
	if cmdString != "" {
		command = cmdString
	} else if len(args) > 0 {
		command = strings.Join(args, " ")
	} else {
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

	manager := sandbox.NewManager(cfg, debug)
	manager.SetExposedPorts(ports)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize sandbox: %w", err)
	}

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence] Sandboxed command: %s\n", sandboxedCommand)
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		if execCmd.Process != nil {
			execCmd.Process.Signal(sig)
		}
		// Give child time to exit, then cleanup will happen via defer
	}()

	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Set exit code but don't os.Exit() here - let deferred cleanup run
			exitCode = exitErr.ExitCode()
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}
