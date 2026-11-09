package common

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseGatewayAddress(t *testing.T) {
	for _, ok := range []string{"", "127.0.0.1", "10.1.1.5", "0.0.0.0", "::", "::1", "fd00::5", "::ffff:10.1.1.5"} {
		got, err := ParseGatewayAddress(ok)
		if err != nil || got != ok {
			t.Errorf("ParseGatewayAddress(%q) = %q, %v; want it back unchanged", ok, got, err)
		}
	}

	for _, bad := range []string{"localhost", "example.org", "fe80::1%eth0", "127.0.0.1:80", "[::1]", "1.2.3", "http://127.0.0.1", " 10.1.1.5", "10.1.1.5 ", "0"} {
		if _, err := ParseGatewayAddress(bad); err == nil {
			t.Errorf("ParseGatewayAddress(%q) accepted", bad)
		}
	}
}

// The default must be the listener CasaOS always had: JoinHostPort("", port) is ":port", every interface.
func TestEmptyAddressBindsEveryInterface(t *testing.T) {
	listener, err := net.Listen("tcp", net.JoinHostPort("", "0"))
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer listener.Close()

	if ip := listener.Addr().(*net.TCPAddr).IP; !ip.IsUnspecified() {
		t.Fatalf("empty address bound %v, want the unspecified address", ip)
	}
}

func TestWaitForGatewayAddress(t *testing.T) {
	ctx := context.Background()

	if err := WaitForGatewayAddress(ctx, "", 0); err != nil {
		t.Fatalf("empty address: %v", err)
	}

	if err := WaitForGatewayAddress(ctx, "127.0.0.1", 0); err != nil {
		t.Fatalf("loopback: %v", err)
	}

	// 192.0.2.1 is TEST-NET-1 (RFC 5737): no machine holds it, so it never binds.
	start := time.Now()
	if err := WaitForGatewayAddress(ctx, "192.0.2.1", 0); err == nil {
		t.Fatal("an address this machine does not hold bound")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("timeout 0 still waited")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := WaitForGatewayAddress(cancelled, "192.0.2.1", time.Minute); err == nil {
		t.Fatal("a cancelled wait returned nil")
	}
}

// What main.go does with a configured address: the listener lands on that address alone.
func TestConfiguredAddressBindsThatAddress(t *testing.T) {
	address, err := ParseGatewayAddress("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer listener.Close()

	if got := listener.Addr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("bound %s, want 127.0.0.1", got)
	}
}
