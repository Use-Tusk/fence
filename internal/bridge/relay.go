package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	defaultUnixSocketMode    = 0o600
	defaultMaxConnections    = 256
	acceptResourceRetryDelay = 50 * time.Millisecond
)

type Spec struct {
	ListenNetwork  string
	ListenAddress  string
	TargetNetwork  string
	TargetAddress  string
	UnlinkExisting bool
	MaxConnections int
}

type Relay struct {
	spec     Spec
	listener net.Listener
	cancel   context.CancelFunc

	closeOnce sync.Once
	wg        sync.WaitGroup

	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	slots         chan struct{}

	errors chan error
}

func Start(ctx context.Context, spec Spec) (*Relay, error) {
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	if spec.ListenNetwork == "unix" && spec.UnlinkExisting {
		if err := os.Remove(spec.ListenAddress); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove existing Unix listener %q: %w", spec.ListenAddress, err)
		}
	}

	listener, err := net.Listen(spec.ListenNetwork, spec.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf(
			"listen on %s %q: %w",
			spec.ListenNetwork,
			spec.ListenAddress,
			err,
		)
	}
	if spec.ListenNetwork == "unix" {
		if err := os.Chmod(spec.ListenAddress, defaultUnixSocketMode); err != nil {
			_ = listener.Close()
			_ = os.Remove(spec.ListenAddress)
			return nil, fmt.Errorf("set Unix listener permissions for %q: %w", spec.ListenAddress, err)
		}
	}

	relayCtx, cancel := context.WithCancel(ctx) // #nosec G118 -- cancel is retained by Relay and called from Close
	maxConnections := spec.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	relay := &Relay{
		spec:        spec,
		listener:    listener,
		cancel:      cancel,
		connections: make(map[net.Conn]struct{}),
		slots:       make(chan struct{}, maxConnections),
		errors:      make(chan error, 1),
	}
	relay.wg.Add(1)
	go relay.acceptLoop(relayCtx)
	go func() {
		<-relayCtx.Done()
		_ = relay.Close()
	}()
	return relay, nil
}

func (r *Relay) Addr() net.Addr {
	return r.listener.Addr()
}

func (r *Relay) Errors() <-chan error {
	return r.errors
}

func (r *Relay) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		r.cancel()
		closeErr = r.listener.Close()
		r.closeConnections()
		r.wg.Wait()
		if r.spec.ListenNetwork == "unix" {
			if err := os.Remove(r.spec.ListenAddress); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
				closeErr = err
			}
		}
		close(r.errors)
	})
	return closeErr
}

func (r *Relay) acceptLoop(ctx context.Context) {
	defer r.wg.Done()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				if isRetryableAcceptResourceError(err) {
					if waitForAcceptRetry(ctx) {
						continue
					}
					return
				}
				select {
				case r.errors <- fmt.Errorf("accept on %s %q: %w", r.spec.ListenNetwork, r.spec.ListenAddress, err):
				default:
				}
			}
			return
		}
		select {
		case r.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		r.trackConnection(conn)
		r.wg.Add(1)
		go r.handleConnection(ctx, conn)
	}
}

func (r *Relay) handleConnection(ctx context.Context, incoming net.Conn) {
	defer r.wg.Done()
	defer func() { <-r.slots }()
	defer r.untrackConnection(incoming)

	target, err := (&net.Dialer{}).DialContext(ctx, r.spec.TargetNetwork, r.spec.TargetAddress)
	if err != nil {
		_ = incoming.Close()
		return
	}
	r.trackConnection(target)
	defer r.untrackConnection(target)

	relayBidirectional(incoming, target)
}

func (r *Relay) trackConnection(conn net.Conn) {
	r.connectionsMu.Lock()
	defer r.connectionsMu.Unlock()
	r.connections[conn] = struct{}{}
}

func (r *Relay) untrackConnection(conn net.Conn) {
	r.connectionsMu.Lock()
	defer r.connectionsMu.Unlock()
	delete(r.connections, conn)
	_ = conn.Close()
}

func (r *Relay) closeConnections() {
	r.connectionsMu.Lock()
	defer r.connectionsMu.Unlock()
	for conn := range r.connections {
		_ = conn.Close()
	}
}

func relayBidirectional(left net.Conn, right net.Conn) {
	done := make(chan error, 2)
	go copyAndHalfClose(left, right, done)
	go copyAndHalfClose(right, left, done)

	firstErr := <-done
	if firstErr != nil {
		_ = left.Close()
		_ = right.Close()
	}
	<-done
	_ = left.Close()
	_ = right.Close()
}

func copyAndHalfClose(dst net.Conn, src net.Conn, done chan<- error) {
	_, err := io.Copy(dst, src)
	if err == nil {
		closeWrite(dst)
		closeRead(src)
	}
	done <- err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := conn.(closeWriter); ok {
		_ = writer.CloseWrite()
	}
}

func closeRead(conn net.Conn) {
	type closeReader interface {
		CloseRead() error
	}
	if reader, ok := conn.(closeReader); ok {
		_ = reader.CloseRead()
	}
}

func validateSpec(spec Spec) error {
	if spec.ListenNetwork != "tcp" && spec.ListenNetwork != "unix" {
		return fmt.Errorf("unsupported listener network %q", spec.ListenNetwork)
	}
	if spec.TargetNetwork != "tcp" && spec.TargetNetwork != "unix" {
		return fmt.Errorf("unsupported target network %q", spec.TargetNetwork)
	}
	if spec.ListenAddress == "" {
		return fmt.Errorf("listener address is empty")
	}
	if spec.TargetAddress == "" {
		return fmt.Errorf("target address is empty")
	}
	if spec.MaxConnections < 0 {
		return fmt.Errorf("maximum connections cannot be negative")
	}
	return nil
}

func isRetryableAcceptResourceError(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

func waitForAcceptRetry(ctx context.Context) bool {
	timer := time.NewTimer(acceptResourceRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
