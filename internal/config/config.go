// Package config defines the configuration types and loading for fence.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Config is the main configuration for fence.
type Config struct {
	Network    NetworkConfig    `json:"network"`
	Filesystem FilesystemConfig `json:"filesystem"`
	AllowPty   bool             `json:"allowPty,omitempty"`
}

// NetworkConfig defines network restrictions.
type NetworkConfig struct {
	AllowedDomains      []string `json:"allowedDomains"`
	DeniedDomains       []string `json:"deniedDomains"`
	AllowUnixSockets    []string `json:"allowUnixSockets,omitempty"`
	AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty"`
	AllowLocalBinding   bool     `json:"allowLocalBinding,omitempty"`
	HTTPProxyPort       int      `json:"httpProxyPort,omitempty"`
	SOCKSProxyPort      int      `json:"socksProxyPort,omitempty"`
}

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig struct {
	DenyRead       []string `json:"denyRead"`
	AllowWrite     []string `json:"allowWrite"`
	DenyWrite      []string `json:"denyWrite"`
	AllowGitConfig bool     `json:"allowGitConfig,omitempty"`
}

// Default returns the default configuration with all network blocked.
func Default() *Config {
	return &Config{
		Network: NetworkConfig{
			AllowedDomains: []string{},
			DeniedDomains:  []string{},
		},
		Filesystem: FilesystemConfig{
			DenyRead:   []string{},
			AllowWrite: []string{},
			DenyWrite:  []string{},
		},
	}
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".fence.json"
	}
	return filepath.Join(home, ".fence.json")
}

// Load loads configuration from a file path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Handle empty file
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	for _, domain := range c.Network.AllowedDomains {
		if err := validateDomainPattern(domain); err != nil {
			return fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
	}
	for _, domain := range c.Network.DeniedDomains {
		if err := validateDomainPattern(domain); err != nil {
			return fmt.Errorf("invalid denied domain %q: %w", domain, err)
		}
	}

	if slices.Contains(c.Filesystem.DenyRead, "") {
		return errors.New("filesystem.denyRead contains empty path")
	}
	if slices.Contains(c.Filesystem.AllowWrite, "") {
		return errors.New("filesystem.allowWrite contains empty path")
	}
	if slices.Contains(c.Filesystem.DenyWrite, "") {
		return errors.New("filesystem.denyWrite contains empty path")
	}

	return nil
}

func validateDomainPattern(pattern string) error {
	if pattern == "localhost" {
		return nil
	}

	if strings.Contains(pattern, "://") || strings.Contains(pattern, "/") || strings.Contains(pattern, ":") {
		return errors.New("domain pattern cannot contain protocol, path, or port")
	}

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		// Must have at least one more dot after the wildcard
		if !strings.Contains(domain, ".") {
			return errors.New("wildcard pattern too broad (e.g., *.com not allowed)")
		}
		if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
			return errors.New("invalid domain format")
		}
		// Check each part has content
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return errors.New("wildcard pattern too broad")
		}
		if slices.Contains(parts, "") {
			return errors.New("invalid domain format")
		}
		return nil
	}

	// Reject other uses of wildcards
	if strings.Contains(pattern, "*") {
		return errors.New("only *.domain.com wildcard patterns are allowed")
	}

	// Regular domains must have at least one dot
	if !strings.Contains(pattern, ".") || strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") {
		return errors.New("invalid domain format")
	}

	return nil
}

// MatchesDomain checks if a hostname matches a domain pattern.
func MatchesDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(hostname)
	pattern = strings.ToLower(pattern)

	// Wildcard pattern like *.example.com
	if strings.HasPrefix(pattern, "*.") {
		baseDomain := pattern[2:]
		return strings.HasSuffix(hostname, "."+baseDomain)
	}

	// Exact match
	return hostname == pattern
}
