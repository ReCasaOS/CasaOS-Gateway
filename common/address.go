package common

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// ParseGatewayAddress checks the `address` key of gateway.ini: empty (every
// interface, dual-stack, what CasaOS has always done) or one IP address.
//
// A name is refused because it would be resolved at every start, to whatever
// the resolver says that day; the rest of CasaOS (the core's fleet and module
// code) only asks a gateway that is bound to an IP. A zone (fe80::1%eth0) is
// refused because the readiness probe URL cannot carry it. The value is
// returned as written: "" stays "" and is never turned into 0.0.0.0, which
// would drop IPv6.
func ParseGatewayAddress(address string) (string, error) {
	if address == "" {
		return "", nil
	}

	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("gateway.ini: address=%q is not an IP address (no host name, no port, no IPv6 zone); leave it empty for every interface", address)
	}

	return address, nil
}

// WaitForGatewayAddress waits up to timeout for this machine to hold address
// (a DHCP lease or a VPN interface that is not up yet when the service starts),
// and returns the last error if it never does. It never falls back to another
// address: the key exists to keep the dashboard off the other networks, and a
// quiet fallback to every interface would undo that.
func WaitForGatewayAddress(ctx context.Context, address string, timeout time.Duration) error {
	if address == "" {
		return nil
	}

	deadline := time.Now().Add(timeout)

	for {
		// Port 0: the kernel picks any free one; the point is only that the address is ours.
		listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
		if err == nil {
			return listener.Close()
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("gateway.ini: address=%s is not an address of this machine: %w", address, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// ParseHTTPSPort checks the `httpsport` key and the API that changes it: empty
// (the default, 443), "0" (no HTTPS listener of the gateway's own) or a port.
func ParseHTTPSPort(port string) (string, error) {
	if port == "" {
		return "", nil
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
		return "", fmt.Errorf("the HTTPS port %q is not 0 (off) or a port from 1 to 65535", port)
	}

	return port, nil
}
