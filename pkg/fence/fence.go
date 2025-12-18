// Package fence provides a public API for sandboxing commands.
package fence

import (
	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/sandbox"
)

// Config is the configuration for fence.
type Config = config.Config

// NetworkConfig defines network restrictions.
type NetworkConfig = config.NetworkConfig

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig = config.FilesystemConfig

// Manager handles sandbox initialization and command wrapping.
type Manager = sandbox.Manager

// NewManager creates a new sandbox manager.
func NewManager(cfg *Config, debug bool) *Manager {
	return sandbox.NewManager(cfg, debug)
}

// DefaultConfig returns the default configuration with all network blocked.
func DefaultConfig() *Config {
	return config.Default()
}

// LoadConfig loads configuration from a file.
func LoadConfig(path string) (*Config, error) {
	return config.Load(path)
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	return config.DefaultConfigPath()
}
