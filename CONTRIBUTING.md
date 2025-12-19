# Contributing

Thanks for helping improve `fence`!

If you have any questions, feel free to open an issue.

## Quick start

- Requirements:
  - Go 1.25+
  - macOS or Linux
- Clone and prepare:

  ```bash
  git clone https://github.com/Use-Tusk/fence
  cd fence
  make setup   # Install deps and lint tools
  make build   # Build the binary
  ./fence --help
  ```

## Dev workflow

Common targets:

| Command | Description |
|---------|-------------|
| `make build` | Build the binary (`./fence`) |
| `make run` | Build and run |
| `make test` | Run tests |
| `make test-ci` | Run tests with coverage |
| `make deps` | Download/tidy modules |
| `make fmt` | Format code with gofumpt |
| `make lint` | Run golangci-lint |
| `make build-ci` | Build with version info (used in CI) |
| `make help` | Show all available targets |

## Code structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full project structure and component details.

## Style and conventions

- Keep edits focused and covered by tests where possible.
- Update [ARCHITECTURE.md](ARCHITECTURE.md) when adding features or changing behavior.
- Prefer small, reviewable PRs with a clear rationale.
- Run `make fmt` and `make lint` before committing.

## Testing

```bash
# Run all tests
make test

# Run with verbose output
go test -v ./...

# Run with coverage
make test-ci
```

### Testing on macOS

```bash
# Test blocked network request
./fence curl https://example.com

# Test with allowed domain
echo '{"network":{"allowedDomains":["example.com"]}}' > /tmp/test.json
./fence -s /tmp/test.json curl https://example.com

# Test monitor mode
./fence -m -c "touch /etc/test"
```

### Testing on Linux

Requires `bubblewrap` and `socat`:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat

# Test in Colima or VM
./fence curl https://example.com
```

## Troubleshooting

**"command not found" after go install:**

- Add `$GOPATH/bin` to your PATH
- Or use `go env GOPATH` to find the path

**Module issues:**

```bash
go mod tidy    # Clean up dependencies
```

**Build cache issues:**

```bash
go clean -cache
go clean -modcache
```

**macOS sandbox issues:**

- Check `log stream --predicate 'eventMessage ENDSWITH "_SBX"'` for violations
- Ensure you're not running as root

**Linux bwrap issues:**

- May need `sudo` or `kernel.unprivileged_userns_clone=1`
- Check that socat and bwrap are installed

## For Maintainers

### Releasing

Releases are automated using [GoReleaser](https://goreleaser.com/) via GitHub Actions.

#### Creating a release

1. Tag the commit with a semantic version:

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. GitHub Actions will automatically:
   - Build binaries for all supported platforms
   - Create archives with README, LICENSE, and ARCHITECTURE.md
   - Generate checksums
   - Create a GitHub release with changelog
   - Upload all artifacts

#### Supported platforms

The release workflow builds for:

- **Linux**: amd64, arm64
- **macOS (darwin)**: amd64, arm64

#### Building locally for distribution

```bash
# Build for current platform
make build

# Cross-compile
make build-linux
make build-darwin

# With version info (mimics CI builds)
make build-ci
```

To test the GoReleaser configuration locally:

```bash
goreleaser release --snapshot --clean
```
