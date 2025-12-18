# fence

A Go implementation of process sandboxing with network and filesystem restrictions.

`fence` wraps arbitrary commands in a security sandbox, blocking network access by default and restricting filesystem operations based on configurable rules.

> [!NOTE]
> This is still a work in progress and may see significant changes.

## Features

- **Network Isolation**: All network access blocked by default
- **Domain Allowlisting**: Configure which domains are allowed
- **Filesystem Restrictions**: Control read/write access to paths
- **Cross-Platform**: macOS (sandbox-exec) and Linux (bubblewrap)
- **HTTP/SOCKS5 Proxies**: Built-in filtering proxies for domain control
- **Library + CLI**: Use as a Go package or command-line tool

## Installation

```bash
go install github.com/Use-Tusk/fence/cmd/fence@latest
```

Or build from source:

```bash
git clone https://github.com/Use-Tusk/fence
cd fence
go build -o fence ./cmd/fence
```

## Quick Start

```bash
# This will be blocked (no domains allowed by default)
fence curl https://example.com

# Run with shell expansion
fence -c "echo hello && ls"

# Enable debug logging
fence -d curl https://example.com
```

## Configuration

Create `~/.fence.json` to configure allowed domains and filesystem access:

```json
{
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org", "registry.yarnpkg.com"],
    "deniedDomains": ["evil.com"]
  },
  "filesystem": {
    "denyRead": ["/etc/passwd"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".git/hooks"]
  }
}
```

### Network Configuration

| Field | Description |
|-------|-------------|
| `allowedDomains` | List of allowed domains. Supports wildcards like `*.example.com` |
| `deniedDomains` | List of denied domains (checked before allowed) |
| `allowUnixSockets` | List of allowed Unix socket paths (macOS) |
| `allowAllUnixSockets` | Allow all Unix sockets |
| `allowLocalBinding` | Allow binding to local ports |

### Filesystem Configuration

| Field | Description |
|-------|-------------|
| `denyRead` | Paths to deny reading (deny-only pattern) |
| `allowWrite` | Paths to allow writing |
| `denyWrite` | Paths to deny writing (takes precedence) |
| `allowGitConfig` | Allow writes to `.git/config` files |

## CLI Usage

```text
fence [flags] [command...]

Flags:
  -c string        Run command string directly (like sh -c)
  -d, --debug      Enable debug logging
  -s, --settings   Path to settings file (default: ~/.fence.json)
  -h, --help       Help for fence
```

### Examples

```bash
# Block all network (default behavior)
fence curl https://example.com
# Output: curl: (7) Couldn't connect to server

# Use a custom config
fence --settings ./my-config.json npm install

# Run a shell command
fence -c "git clone https://github.com/user/repo && cd repo && npm install"

# Debug mode shows proxy activity
fence -d wget https://example.com
```

## Library Usage

```go
package main

import (
    "fmt"
    "github.com/Use-Tusk/fence/pkg/fence"
)

func main() {
    // Create config
    cfg := &fence.Config{
        Network: fence.NetworkConfig{
            AllowedDomains: []string{"api.example.com"},
        },
        Filesystem: fence.FilesystemConfig{
            AllowWrite: []string{"."},
        },
    }

    // Create manager
    manager := fence.NewManager(cfg, false)
    defer manager.Cleanup()

    // Initialize (starts proxies)
    if err := manager.Initialize(); err != nil {
        panic(err)
    }

    // Wrap a command
    wrapped, err := manager.WrapCommand("curl https://api.example.com/data")
    if err != nil {
        panic(err)
    }

    fmt.Println("Sandboxed command:", wrapped)
}
```

## How It Works

### macOS (sandbox-exec)

On macOS, fence uses Apple's `sandbox-exec` with a generated seatbelt profile that:

- Denies all operations by default
- Allows specific Mach services needed for basic operation
- Controls network access via localhost proxies
- Restricts filesystem read/write based on configuration

### Linux (bubblewrap)

On Linux, fence uses `bubblewrap` (bwrap) with:

- Network namespace isolation (`--unshare-net`)
- Filesystem bind mounts for access control
- PID namespace isolation
- Unix socket bridges for proxy communication

For detailed security model, limitations, and architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

### macOS

- macOS 10.12+ (uses `sandbox-exec`)
- No additional dependencies

### Linux

- `bubblewrap` (bwrap)
- `socat` (for network bridging)

Install on Ubuntu/Debian:

```bash
apt install bubblewrap socat
```

## License

Apache-2.0
