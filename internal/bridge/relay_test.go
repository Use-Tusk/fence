package bridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayBidirectionalDrainsAfterClientHalfClose(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for target: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		request, err := io.ReadAll(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if string(request) != "request" {
			serverDone <- fmt.Errorf("request = %q, want %q", request, "request")
			return
		}
		_, err = conn.Write([]byte("response"))
		serverDone <- err
	}()

	relay, err := Start(context.Background(), Spec{
		ListenNetwork: "tcp",
		ListenAddress: "127.0.0.1:0",
		TargetNetwork: "tcp",
		TargetAddress: targetListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = relay.Close() }()

	client, err := net.DialTCP("tcp", nil, relay.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("half-close request: %v", err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q, want %q", response, "response")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("target server error: %v", err)
	}
}

func TestRelayUnixListenerUsesPrivatePermissionsAndCleansUp(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for target: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	socketDir, err := os.MkdirTemp("/tmp", "fence-relay-")
	if err != nil {
		t.Fatalf("create short Unix socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "relay.sock")
	relay, err := Start(context.Background(), Spec{
		ListenNetwork: "unix",
		ListenAddress: socketPath,
		TargetNetwork: "tcp",
		TargetAddress: targetListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat Unix listener: %v", err)
	}
	if got := info.Mode().Perm(); got != defaultUnixSocketMode {
		t.Fatalf("Unix listener mode = %#o, want %#o", got, defaultUnixSocketMode)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("Unix listener still exists after Close(): %v", err)
	}
}

func TestRelayContextCancellationClosesActiveConnections(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for target: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	targetAccepted := make(chan struct{})
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		close(targetAccepted)
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	relay, err := Start(ctx, Spec{
		ListenNetwork: "tcp",
		ListenAddress: "127.0.0.1:0",
		TargetNetwork: "tcp",
		TargetAddress: targetListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client, err := net.Dial("tcp", relay.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("connected")); err != nil {
		t.Fatalf("write through relay: %v", err)
	}
	select {
	case <-targetAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not accept relayed connection")
	}

	cancel()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client read succeeded after relay cancellation")
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
