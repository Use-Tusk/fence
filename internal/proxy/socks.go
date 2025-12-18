package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/things-go/go-socks5"
)

// SOCKSProxy is a SOCKS5 proxy server with domain filtering.
type SOCKSProxy struct {
	server   *socks5.Server
	listener net.Listener
	filter   FilterFunc
	debug    bool
	port     int
}

// NewSOCKSProxy creates a new SOCKS5 proxy with the given filter.
func NewSOCKSProxy(filter FilterFunc, debug bool) *SOCKSProxy {
	return &SOCKSProxy{
		filter: filter,
		debug:  debug,
	}
}

// fenceRuleSet implements socks5.RuleSet for domain filtering.
type fenceRuleSet struct {
	filter FilterFunc
	debug  bool
}

func (r *fenceRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	host := req.DestAddr.FQDN
	if host == "" {
		host = req.DestAddr.IP.String()
	}
	port := req.DestAddr.Port

	allowed := r.filter(host, port)
	if r.debug {
		if allowed {
			fmt.Printf("[fence:socks] Allowed: %s:%d\n", host, port)
		} else {
			fmt.Printf("[fence:socks] Blocked: %s:%d\n", host, port)
		}
	}
	return ctx, allowed
}

// Start starts the SOCKS5 proxy on a random available port.
func (p *SOCKSProxy) Start() (int, error) {
	// Create listener first to get a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen: %w", err)
	}
	p.listener = listener
	p.port = listener.Addr().(*net.TCPAddr).Port

	server := socks5.NewServer(
		socks5.WithRule(&fenceRuleSet{
			filter: p.filter,
			debug:  p.debug,
		}),
	)
	p.server = server

	go func() {
		if err := p.server.Serve(p.listener); err != nil {
			if p.debug {
				fmt.Printf("[fence:socks] Server error: %v\n", err)
			}
		}
	}()

	if p.debug {
		fmt.Printf("[fence:socks] SOCKS5 proxy listening on localhost:%d\n", p.port)
	}
	return p.port, nil
}

// Stop stops the SOCKS5 proxy.
func (p *SOCKSProxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Port returns the port the proxy is listening on.
func (p *SOCKSProxy) Port() int {
	return p.port
}
