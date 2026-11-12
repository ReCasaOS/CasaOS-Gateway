package guard

import "testing"

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9:4444":         "203.0.113.9",
		"[::ffff:203.0.113.9]:1":   "203.0.113.9",
		"[2001:db8:1:2:aaaa::1]:1": "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9]:1": "2001:db8:1:2::/64",
		"not an address":           "not an address",
	} {
		key, ip := Key(in)
		if key != want {
			t.Errorf("Key(%q) key = %q, want %q", in, key, want)
		}
		if in == "[2001:db8:1:2:aaaa::1]:1" && ip != "2001:db8:1:2:aaaa::1" {
			t.Errorf("ip = %q", ip)
		}
		if in == "not an address" && ip != in {
			t.Errorf("ip = %q, want unchanged", ip)
		}
	}
}
