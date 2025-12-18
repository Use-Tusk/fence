package sandbox

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ContainsGlobChars checks if a path pattern contains glob characters.
func ContainsGlobChars(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[]")
}

// RemoveTrailingGlobSuffix removes trailing /** from a path pattern.
func RemoveTrailingGlobSuffix(pattern string) string {
	return strings.TrimSuffix(pattern, "/**")
}

// NormalizePath normalizes a path for sandbox configuration.
// Handles tilde expansion and relative paths.
func NormalizePath(pathPattern string) string {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	normalized := pathPattern

	// Expand ~ to home directory
	if pathPattern == "~" {
		normalized = home
	} else if strings.HasPrefix(pathPattern, "~/") {
		normalized = filepath.Join(home, pathPattern[2:])
	} else if strings.HasPrefix(pathPattern, "./") || strings.HasPrefix(pathPattern, "../") {
		normalized, _ = filepath.Abs(filepath.Join(cwd, pathPattern))
	} else if !filepath.IsAbs(pathPattern) && !ContainsGlobChars(pathPattern) {
		normalized, _ = filepath.Abs(filepath.Join(cwd, pathPattern))
	}

	// For non-glob patterns, try to resolve symlinks
	if !ContainsGlobChars(normalized) {
		if resolved, err := filepath.EvalSymlinks(normalized); err == nil {
			return resolved
		}
	}

	return normalized
}

// GenerateProxyEnvVars creates environment variables for proxy configuration.
func GenerateProxyEnvVars(httpPort, socksPort int) []string {
	envVars := []string{
		"FENCE_SANDBOX=1",
		"TMPDIR=/tmp/fence",
	}

	if httpPort == 0 && socksPort == 0 {
		return envVars
	}

	// NO_PROXY for localhost and private networks
	noProxy := strings.Join([]string{
		"localhost",
		"127.0.0.1",
		"::1",
		"*.local",
		".local",
		"169.254.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}, ",")

	envVars = append(envVars,
		"NO_PROXY="+noProxy,
		"no_proxy="+noProxy,
	)

	if httpPort > 0 {
		proxyURL := "http://localhost:" + itoa(httpPort)
		envVars = append(envVars,
			"HTTP_PROXY="+proxyURL,
			"HTTPS_PROXY="+proxyURL,
			"http_proxy="+proxyURL,
			"https_proxy="+proxyURL,
		)
	}

	if socksPort > 0 {
		socksURL := "socks5h://localhost:" + itoa(socksPort)
		envVars = append(envVars,
			"ALL_PROXY="+socksURL,
			"all_proxy="+socksURL,
			"FTP_PROXY="+socksURL,
			"ftp_proxy="+socksURL,
		)
		// Git SSH through SOCKS
		envVars = append(envVars,
			"GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:"+itoa(socksPort)+" %h %p'",
		)
	}

	return envVars
}

// EncodeSandboxedCommand encodes a command for sandbox monitoring.
func EncodeSandboxedCommand(command string) string {
	if len(command) > 100 {
		command = command[:100]
	}
	return base64.StdEncoding.EncodeToString([]byte(command))
}

// DecodeSandboxedCommand decodes a base64-encoded command.
func DecodeSandboxedCommand(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
