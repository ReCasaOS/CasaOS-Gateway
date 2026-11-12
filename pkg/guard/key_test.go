package guard

import "testing"

func TestKey(t *testing.T) {
	for _, c := range []struct{ in, key, ip string }{
		{"203.0.113.9:4444", "203.0.113.9", "203.0.113.9"},
		{"[::ffff:203.0.113.9]:1", "203.0.113.9", "203.0.113.9"},
		{"[2001:db8:1:2:aaaa::1]:1", "2001:db8:1:2::/64", "2001:db8:1:2:aaaa::1"},
		{"[2001:db8:1:2:bbbb::9]:1", "2001:db8:1:2::/64", "2001:db8:1:2:bbbb::9"},
		{"[fe80::1%eth0]:1", "fe80::/64", "fe80::1"},
		{"not an address", "not an address", "not an address"},
	} {
		if key, ip := Key(c.in); key != c.key || ip != c.ip {
			t.Errorf("Key(%q) = %q, %q; want %q, %q", c.in, key, ip, c.key, c.ip)
		}
	}
}
