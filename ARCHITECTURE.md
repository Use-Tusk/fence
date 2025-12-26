# Architecture

Fence restricts network and filesystem access for arbitrary commands. It works by:

1. **Intercepting network traffic** via HTTP/SOCKS5 proxies that filter by domain
2. **Sandboxing processes** using OS-native mechanisms (macOS sandbox-exec, Linux bubblewrap)
3. **Bridging connections** to allow controlled inbound/outbound traffic in isolated namespaces

```mermaid
flowchart TB
    subgraph Fence
        Config["Config<br/>(JSON)"]
        Manager
        Sandbox["Platform Sandbox<br/>(macOS/Linux)"]
        HTTP["HTTP Proxy<br/>(filtering)"]
        SOCKS["SOCKS5 Proxy<br/>(filtering)"]
    end

    Config --> Manager
    Manager --> Sandbox
    Manager --> HTTP
    Manager --> SOCKS
```

## Project Structure

```text
fence/
├── cmd/fence/           # CLI entry point
│   └── main.go          # Includes --landlock-apply wrapper mode
├── internal/            # Private implementation
│   ├── config/          # Configuration loading/validation
│   ├── platform/        # OS detection
│   ├── proxy/           # HTTP and SOCKS5 filtering proxies
│   └── sandbox/         # Platform-specific sandboxing
│       ├── manager.go   # Orchestrates sandbox lifecycle
│       ├── macos.go     # macOS sandbox-exec profiles
│       ├── linux.go     # Linux bubblewrap + socat bridges
│       ├── linux_seccomp.go    # Seccomp BPF syscall filtering
│       ├── linux_landlock.go   # Landlock filesystem control
│       ├── linux_ebpf.go       # eBPF violation monitoring
│       ├── linux_features.go   # Kernel feature detection
│       ├── linux_*_stub.go     # Non-Linux build stubs
│       ├── monitor.go   # macOS log stream violation monitoring
│       ├── dangerous.go # Protected file/directory lists
│       ├── shell.go     # Shell quoting utilities
│       └── utils.go     # Path normalization
└── pkg/fence/           # Public Go API
    └── fence.go
```

## Core Components

### Config (`internal/config/`)

Handles loading and validating sandbox configuration:

```go
type Config struct {
    Network    NetworkConfig    // Domain allow/deny lists
    Filesystem FilesystemConfig // Read/write restrictions
    AllowPty   bool             // Allow pseudo-terminal allocation
}
```

- Loads from `~/.fence.json` or custom path
- Falls back to restrictive defaults (block all network)
- Validates paths and normalizes them

### Platform (`internal/platform/`)

Simple OS detection:

```go
func Detect() Platform  // Returns MacOS, Linux, Windows, or Unknown
func IsSupported() bool // True for MacOS and Linux
```

### Proxy (`internal/proxy/`)

Two proxy servers that filter traffic by domain:

#### HTTP Proxy (`http.go`)

- Handles HTTP and HTTPS (via CONNECT tunneling)
- Extracts domain from Host header or CONNECT request
- Returns 403 for blocked domains
- Listens on random available port

#### SOCKS5 Proxy (`socks.go`)

- Uses `github.com/things-go/go-socks5`
- Handles TCP connections (git, ssh, etc.)
- Same domain filtering logic as HTTP proxy
- Listens on random available port

**Domain Matching:**

- Exact match: `example.com`
- Wildcard prefix: `*.example.com` (matches `api.example.com`)
- Deny takes precedence over allow

### Sandbox (`internal/sandbox/`)

#### Manager (`manager.go`)

Orchestrates the sandbox lifecycle:

1. Initializes HTTP and SOCKS proxies
2. Sets up platform-specific bridges (Linux)
3. Wraps commands with sandbox restrictions
4. Handles cleanup on exit

#### macOS Implementation (`macos.go`)

Uses Apple's `sandbox-exec` with Seatbelt profiles:

```mermaid
flowchart LR
    subgraph macOS Sandbox
        CMD["User Command"]
        SE["sandbox-exec -p profile"]
        ENV["Environment Variables<br/>HTTP_PROXY, HTTPS_PROXY<br/>ALL_PROXY, GIT_SSH_COMMAND"]
    end

    subgraph Profile Controls
        NET["Network: deny except localhost"]
        FS["Filesystem: read/write rules"]
        PROC["Process: fork/exec permissions"]
    end

    CMD --> SE
    SE --> ENV
    SE -.-> NET
    SE -.-> FS
    SE -.-> PROC
```

Seatbelt profiles are generated dynamically based on config:

- `(deny default)` - deny all by default
- `(allow network-outbound (remote ip "localhost:*"))` - only allow proxy
- `(allow file-read* ...)` - selective file access
- `(allow process-fork)`, `(allow process-exec)` - allow running programs

#### Linux Implementation (`linux.go`)

Uses `bubblewrap` (bwrap) with network namespace isolation:

```mermaid
flowchart TB
    subgraph Host
        HTTP["HTTP Proxy<br/>:random"]
        SOCKS["SOCKS Proxy<br/>:random"]
        HSOCAT["socat<br/>(HTTP bridge)"]
        SSOCAT["socat<br/>(SOCKS bridge)"]
        USOCK["Unix Sockets<br/>/tmp/fence-*.sock"]
    end

    subgraph Sandbox ["Sandbox (bwrap --unshare-net)"]
        CMD["User Command"]
        ISOCAT["socat :3128"]
        ISOCKS["socat :1080"]
        ENV2["HTTP_PROXY=127.0.0.1:3128"]
    end

    HTTP <--> HSOCAT
    SOCKS <--> SSOCAT
    HSOCAT <--> USOCK
    SSOCAT <--> USOCK
    USOCK <-->|bind-mounted| ISOCAT
    USOCK <-->|bind-mounted| ISOCKS
    CMD --> ISOCAT
    CMD --> ISOCKS
    CMD -.-> ENV2
```

**Why socat bridges?**

With `--unshare-net`, the sandbox has its own isolated network namespace - it cannot reach the host's network at all. Unix sockets provide filesystem-based IPC that works across namespace boundaries:

1. Host creates Unix socket, connects to TCP proxy
2. Socket file is bind-mounted into sandbox
3. Sandbox's socat listens on localhost:3128, forwards to Unix socket
4. Traffic flows: `sandbox:3128 → Unix socket → host proxy → internet`

## Inbound Connections (Reverse Bridge)

For servers running inside the sandbox that need to accept connections:

```mermaid
flowchart TB
    EXT["External Request"]

    subgraph Host
        HSOCAT["socat<br/>TCP-LISTEN:8888"]
        USOCK["Unix Socket<br/>/tmp/fence-rev-8888-*.sock"]
    end

    subgraph Sandbox
        ISOCAT["socat<br/>UNIX-LISTEN"]
        APP["App Server<br/>:8888"]
    end

    EXT --> HSOCAT
    HSOCAT -->|UNIX-CONNECT| USOCK
    USOCK <-->|shared via bind /| ISOCAT
    ISOCAT --> APP
```

Flow:

1. Host socat listens on TCP port (e.g., 8888)
2. Sandbox socat creates Unix socket, forwards to app
3. External request → Host:8888 → Unix socket → Sandbox socat → App:8888

## Execution Flow

```mermaid
flowchart TD
    A["1. CLI parses arguments"] --> B["2. Load config from ~/.fence.json"]
    B --> C["3. Create Manager"]
    C --> D["4. Manager.Initialize()"]

    D --> D1["Start HTTP proxy"]
    D --> D2["Start SOCKS proxy"]
    D --> D3["[Linux] Create socat bridges"]
    D --> D4["[Linux] Create reverse bridges"]

    D1 & D2 & D3 & D4 --> E["5. Manager.WrapCommand()"]

    E --> E1["[macOS] Generate Seatbelt profile"]
    E --> E2["[Linux] Generate bwrap command"]

    E1 & E2 --> F["6. Execute wrapped command"]
    F --> G["7. Manager.Cleanup()"]

    G --> G1["Kill socat processes"]
    G --> G2["Remove Unix sockets"]
    G --> G3["Stop proxy servers"]
```

## Platform Comparison

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox mechanism | sandbox-exec (Seatbelt) | bubblewrap + Landlock + seccomp |
| Network isolation | Syscall filtering | Network namespace |
| Proxy routing | Environment variables | socat bridges + env vars |
| Filesystem control | Profile rules | Bind mounts + Landlock (5.13+) |
| Syscall filtering | Implicit (Seatbelt) | seccomp BPF |
| Inbound connections | Profile rules (`network-bind`) | Reverse socat bridges |
| Violation monitoring | log stream + proxy | eBPF + proxy |
| Requirements | Built-in | bwrap, socat |

### Linux Security Layers

On Linux, fence uses multiple security layers with graceful fallback:

1. bubblewrap (core isolation via Linux namespaces)
2. seccomp (syscall filtering)
3. Landlock (filesystem access control)
4. eBPF monitoring (violation visibility)

> [!NOTE]
> Seccomp blocks syscalls silently (no logging). With `-m` and root/CAP_BPF, the eBPF monitor catches these failures by tracing syscall exits that return EPERM/EACCES.

See [Linux Security Features](./docs/linux-security-features.md) for details.

## Violation Monitoring

The `-m` (monitor) flag enables real-time visibility into blocked operations.

### Output Prefixes

| Prefix | Source | Description |
|--------|--------|-------------|
| `[fence:http]` | Both | HTTP/HTTPS proxy (blocked requests only in monitor mode) |
| `[fence:socks]` | Both | SOCKS5 proxy (blocked requests only in monitor mode) |
| `[fence:logstream]` | macOS only | Kernel-level sandbox violations from `log stream` |
| `[fence:ebpf]` | Linux only | Filesystem/syscall failures (requires CAP_BPF or root) |
| `[fence:filter]` | Both | Domain filter rule matches (debug mode only) |

### macOS Log Stream

On macOS, fence spawns `log stream` with a predicate to capture sandbox violations:

```bash
log stream --predicate 'eventMessage ENDSWITH "_SBX"' --style compact
```

Violations include:

- `network-outbound` - blocked network connections
- `file-read*` - blocked file reads
- `file-write*` - blocked file writes

Filtered out (too noisy):

- `mach-lookup` - IPC service lookups
- `file-ioctl` - device control operations
- `/dev/tty*` writes - terminal output
- `mDNSResponder` - system DNS resolution
- `/private/var/run/syslog` - system logging

### Debug vs Monitor Mode

| Flag | Proxy logs | Filter rules | Log stream | Sandbox command |
|------|------------|--------------|------------|-----------------|
| `-m` | Blocked only | No | Yes (macOS) | No |
| `-d` | All | Yes | No | Yes |
| `-m -d` | All | Yes | Yes (macOS) | Yes |

## Security Model

See [`docs/security-model.md`](docs/security-model.md) for Fence's threat model, guarantees, and limitations.
