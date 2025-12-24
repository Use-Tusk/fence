# Fence

![GitHub Release](https://img.shields.io/github/v/release/Use-Tusk/fence)

A Go implementation of process sandboxing with network and filesystem restrictions.

Fence wraps commands in a sandbox that blocks network access by default and restricts filesystem operations based on configurable rules. It's most useful for running semi-trusted code (package installs, build scripts, CI jobs, unfamiliar repos) with controlled side effects, and it can also complement AI coding agents as defense-in-depth.

## Features

- **Network Isolation**: All network access blocked by default
- **Domain Allowlisting**: Configure which domains are allowed
- **Filesystem Restrictions**: Control read/write access to paths
- **Violation Monitoring**: Real-time logging of blocked requests and sandbox denials
- **Cross-Platform**: macOS (sandbox-exec) and Linux (bubblewrap)
- **HTTP/SOCKS5 Proxies**: Built-in filtering proxies for domain control

You can use Fence as a Go package or CLI tool.

## Documentation

- [Documentation index](docs/)
- [Security model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Examples](examples/)

## Installation

At the moment, we only support MacOS and Linux. For Windows users, we recommend using WSL.

```bash
go install github.com/Use-Tusk/fence/cmd/fence@latest
```

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/Use-Tusk/fence
cd fence
go build -o fence ./cmd/fence
```

</details>

**Additional requirements for Linux:**

- `bubblewrap` (for sandboxing)
- `socat` (for network bridging)

## Quick Start

```bash
# This will be blocked (no domains allowed by default)
fence curl https://example.com

# Run with shell expansion
fence -c "echo hello && ls"

# Enable debug logging
fence -d curl https://example.com
```

For a more detailed introduction, see the [Quickstart Guide](docs/quickstart.md).

## CLI Usage

```text
fence [flags] -- [command...]

Flags:
  -c string        Run command string directly (like sh -c)
  -d, --debug      Enable debug logging (shows sandbox command, proxy activity, filter rules)
  -m, --monitor    Monitor mode (shows blocked requests and violations only)
  -p, --port       Expose port for inbound connections (can be repeated)
  -s, --settings   Path to settings file (default: ~/.fence.json)
  -v, --version    Show version information
  -h, --help       Help for fence
```

### Examples

```bash
# Block all network (default behavior)
fence curl https://example.com
# Output: curl: (56) CONNECT tunnel failed, response 403

# Use a custom config
fence --settings ./my-config.json npm install

# Run a shell command
fence -c "git clone https://github.com/user/repo && cd repo && npm install"

# Debug mode shows proxy activity
fence -d wget https://example.com

# Monitor mode shows violations/blocked requests only
fence -m npm install

# Expose a port for inbound connections
fence -p 3000 -c "npm run dev"
```

## Library Usage

```go
package main

import (
    "fmt"
    "github.com/Use-Tusk/fence/pkg/fence"
)

func main() {
    // Check if platform supports sandboxing (macOS/Linux)
    if !fence.IsSupported() {
        fmt.Println("Sandboxing not supported on this platform")
        return
    }

    // Create config
    cfg := &fence.Config{
        Network: fence.NetworkConfig{
            AllowedDomains: []string{"api.example.com"},
        },
        Filesystem: fence.FilesystemConfig{
            AllowWrite: []string{"."},
        },
    }

    // Create manager (debug=false, monitor=false)
    manager := fence.NewManager(cfg, false, false)
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

## Attribution

Portions of this project are derived from Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) (Apache-2.0). This repository contains modifications and additional original work.
