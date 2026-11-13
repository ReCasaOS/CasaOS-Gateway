package guard

import "net/netip"

// Key is the ban key of a visitor: the IPv4 address (IPv4-mapped IPv6 is IPv4), or the IPv6 /64
// written <prefix>::/64. ip is the plain address. A RemoteAddr that does not parse comes back
// unchanged as both.
func Key(remoteAddr string) (key, ip string) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return remoteAddr, remoteAddr
	}
	a := ap.Addr().Unmap().WithZone("")
	if a.Is4() {
		return a.String(), a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String(), a.String()
}
