package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const exampleConfig = `{
  "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  "protection": true,
  "apps": {
    "jellyfin.mybox.box.recasaos.org": {
      "app": "jellyfin",
      "access": "code",
      "policy": {
        "waf": "observe",
        "rules_off": [942100],
        "allow": ["192.0.2.0/24"],
        "block": ["198.51.100.7", "2001:db8::/32"],
        "countries": { "mode": "block", "list": ["XX"] },
        "rate_per_min": 600,
        "ban": { "waf_hits": 10, "waf_window_s": 600, "scan_404": 100, "scan_window_s": 60,
                 "rate_strikes": 3, "rate_window_s": 600, "code_fails": 5, "code_window_s": 600 }
      }
    }
  },
  "people": [ { "id": "p_7f3a", "gen": 2, "code_hash": "499b46abdc484007465c1451c284ae4485de2006d52fd01cc6fa0f0c6eed12c2", "apps": ["jellyfin"] } ]
}`

func example(t *testing.T) Config {
	t.Helper()
	var c Config
	if err := json.Unmarshal([]byte(exampleConfig), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigValidate(t *testing.T) {
	c := example(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("the contract's example must validate: %v", err)
	}
	if len(c.Secret) != 32 {
		t.Fatalf("secret decoded to %d bytes", len(c.Secret))
	}

	const host = "jellyfin.mybox.box.recasaos.org"
	cases := []struct {
		name   string
		mutate func(c *Config)
		field  string
	}{
		{"access", func(c *Config) { a := c.Apps[host]; a.Access = "x"; c.Apps[host] = a }, `apps["` + host + `"].access`},
		{"waf", func(c *Config) { a := c.Apps[host]; a.Policy.WAF = "x"; c.Apps[host] = a }, ".policy.waf"},
		{"countries mode", func(c *Config) { a := c.Apps[host]; a.Policy.Countries.Mode = "x"; c.Apps[host] = a }, ".policy.countries.mode"},
		{"countries list", func(c *Config) { a := c.Apps[host]; a.Policy.Countries.List = []string{"fr"}; c.Apps[host] = a }, ".policy.countries.list[0]"},
		{"allow", func(c *Config) { a := c.Apps[host]; a.Policy.Allow = []string{"300.1.1.1"}; c.Apps[host] = a }, ".policy.allow[0]: not an IP or CIDR"},
		{"block", func(c *Config) { a := c.Apps[host]; a.Policy.Block = []string{"ok", "1.2.3.4"}; c.Apps[host] = a }, ".policy.block[0]: not an IP or CIDR"},
		{"rate", func(c *Config) { a := c.Apps[host]; a.Policy.RatePerMin = 0; c.Apps[host] = a }, ".policy.rate_per_min"},
		{"ban", func(c *Config) { a := c.Apps[host]; a.Policy.Ban.CodeFails = 0; c.Apps[host] = a }, ".policy.ban.code_fails"},
		{"secret", func(c *Config) { c.Secret = c.Secret[:16] }, "secret"},
		{"code hash", func(c *Config) { c.People[0].CodeHash = "abc" }, "people[0].code_hash"},
		{"person id", func(c *Config) { c.People[0].ID = "" }, "people[0].id"},
		{"host case", func(c *Config) { c.Apps["Jellyfin.mybox.box.recasaos.org"] = c.Apps[host]; delete(c.Apps, host) }, `apps["Jellyfin.mybox.box.recasaos.org"]: not a normalised host`},
		{"host dot", func(c *Config) { c.Apps[host+"."] = c.Apps[host]; delete(c.Apps, host) }, `apps["` + host + `."]: not a normalised host`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := example(t)
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want an error naming %q, got %v", tc.field, err)
			}
		})
	}
}

func TestSetConfigPersists(t *testing.T) {
	rt, data := t.TempDir(), t.TempDir()
	now := func() time.Time { return time.Unix(0, 0) }

	g, err := New(rt, data, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.Configured() {
		t.Fatal("a fresh guard is not configured")
	}

	want := example(t)
	if err := g.SetConfig(want); err != nil {
		t.Fatal(err)
	}
	if !g.Configured() {
		t.Fatal("not configured after SetConfig")
	}

	bad := example(t)
	bad.Secret = bad.Secret[:3]
	if err := g.SetConfig(bad); err == nil {
		t.Fatal("a bad config must be refused")
	}

	g2, err := New(rt, data, now)
	if err != nil {
		t.Fatal(err)
	}
	if !g2.Configured() {
		t.Fatal("reloaded guard is not configured")
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(g2.Config())
	if string(a) != string(b) {
		t.Fatalf("reloaded config differs:\n%s\n%s", a, b)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(rt, FileName))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("guard.json mode %v", fi.Mode().Perm())
		}
	}
}

func TestCorruptFileStartsBroken(t *testing.T) {
	rt := t.TempDir()
	g, err := New(rt, t.TempDir(), time.Now)
	if err != nil || g.Broken() {
		t.Fatalf("a missing file is the normal unconfigured state: err=%v broken=%v", err, g.Broken())
	}

	for _, content := range []string{"{not json", `{"apps":{"a.b.c":{"access":"x"}}}`} {
		if err := os.WriteFile(filepath.Join(rt, FileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		g, err := New(rt, t.TempDir(), time.Now)
		if err != nil {
			t.Fatalf("New must not fail on a corrupt file: %v", err)
		}
		if !g.Broken() || g.Configured() {
			t.Fatalf("%q: broken=%v configured=%v", content, g.Broken(), g.Configured())
		}
		if err := g.SetConfig(example(t)); err != nil {
			t.Fatal(err)
		}
		if g.Broken() || !g.Configured() {
			t.Fatal("a valid SetConfig must clear broken")
		}
	}
}

func TestStatusNeverNull(t *testing.T) {
	g, err := New(t.TempDir(), t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(g.Status())
	want := `{"version":1,"configured":false,"geo":{"country":false,"asn":false},"people_last_used":{},"waves":[]}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}
