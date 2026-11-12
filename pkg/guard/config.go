// Package guard protects the apps shared on the internet: the config the core pushes, and the
// filters built on it.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// FileName is the pushed config, in the runtime path next to hosts.json.
const FileName = "guard.json"

// ErrInvalid wraps every validation failure, so the API can answer 400 rather than 500.
var ErrInvalid = errors.New("invalid guard config")

type Config struct {
	Secret     []byte               `json:"secret"` // base64 std in JSON
	Protection bool                 `json:"protection"`
	Apps       map[string]AppConfig `json:"apps"` // keyed by host
	People     []Person             `json:"people"`
}

type AppConfig struct {
	App    string `json:"app"`
	Access string `json:"access"` // "open" or "code"
	Policy Policy `json:"policy"`
}

type Policy struct {
	WAF        string    `json:"waf"` // "off", "observe", "block"
	RulesOff   []int     `json:"rules_off"`
	Allow      []string  `json:"allow"`
	Block      []string  `json:"block"`
	Countries  Countries `json:"countries"`
	RatePerMin int       `json:"rate_per_min"`
	Ban        BanRules  `json:"ban"`
}

type Countries struct {
	Mode string   `json:"mode"` // "none", "block", "allow"
	List []string `json:"list"` // ISO 3166-1 alpha-2, uppercase
}

type BanRules struct {
	WAFHits     int `json:"waf_hits"`
	WAFWindowS  int `json:"waf_window_s"`
	Scan404     int `json:"scan_404"`
	ScanWindowS int `json:"scan_window_s"`
	RateStrikes int `json:"rate_strikes"`
	RateWindowS int `json:"rate_window_s"`
	CodeFails   int `json:"code_fails"`
	CodeWindowS int `json:"code_window_s"`
}

type Person struct {
	ID       string   `json:"id"`
	Gen      int      `json:"gen"`
	CodeHash string   `json:"code_hash"` // 64 lowercase hex
	Apps     []string `json:"apps"`
}

var (
	countryPattern  = regexp.MustCompile(`^[A-Z]{2}$`)
	codeHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validIPOrCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate names the first offending field, e.g. apps["x"].policy.allow[0]: not an IP or CIDR.
func (c Config) Validate() error {
	if n := len(c.Secret); n != 0 && n != 32 { // empty: the Gateway then answers 503 on code hosts
		return invalid("secret: %d bytes, want 32", n)
	}
	for host, a := range c.Apps {
		if err := a.validate(fmt.Sprintf("apps[%q]", host)); err != nil {
			return err
		}
	}
	for i, person := range c.People {
		if person.ID == "" {
			return invalid("people[%d].id: empty", i)
		}
		if !codeHashPattern.MatchString(person.CodeHash) {
			return invalid("people[%d].code_hash: not 64 lowercase hex characters", i)
		}
	}
	return nil
}

func (a AppConfig) validate(p string) error {
	if a.Access != "open" && a.Access != "code" {
		return invalid(`%s.access: %q, want "open" or "code"`, p, a.Access)
	}
	pol := a.Policy
	p += ".policy"
	if pol.WAF != "off" && pol.WAF != "observe" && pol.WAF != "block" {
		return invalid(`%s.waf: %q, want "off", "observe" or "block"`, p, pol.WAF)
	}
	for i, id := range pol.RulesOff {
		if id <= 0 {
			return invalid("%s.rules_off[%d]: not a rule id", p, i)
		}
	}
	for i, s := range pol.Allow {
		if !validIPOrCIDR(s) {
			return invalid("%s.allow[%d]: not an IP or CIDR", p, i)
		}
	}
	for i, s := range pol.Block {
		if !validIPOrCIDR(s) {
			return invalid("%s.block[%d]: not an IP or CIDR", p, i)
		}
	}
	if m := pol.Countries.Mode; m != "none" && m != "block" && m != "allow" {
		return invalid(`%s.countries.mode: %q, want "none", "block" or "allow"`, p, m)
	}
	for i, cc := range pol.Countries.List {
		if !countryPattern.MatchString(cc) {
			return invalid("%s.countries.list[%d]: not an uppercase ISO 3166-1 alpha-2 code", p, i)
		}
	}
	if pol.RatePerMin <= 0 {
		return invalid("%s.rate_per_min: must be positive", p)
	}
	b := pol.Ban
	for _, f := range []struct {
		name string
		v    int
	}{
		{"waf_hits", b.WAFHits}, {"waf_window_s", b.WAFWindowS}, {"scan_404", b.Scan404}, {"scan_window_s", b.ScanWindowS},
		{"rate_strikes", b.RateStrikes}, {"rate_window_s", b.RateWindowS}, {"code_fails", b.CodeFails}, {"code_window_s", b.CodeWindowS},
	} {
		if f.v <= 0 {
			return invalid("%s.ban.%s: must be positive", p, f.name)
		}
	}
	return nil
}

// Status is the body of GET /v1/gateway/guard.
type Status struct {
	Version        int                  `json:"version"`
	Configured     bool                 `json:"configured"`
	Geo            GeoStatus            `json:"geo"`
	PeopleLastUsed map[string]time.Time `json:"people_last_used"`
	Waves          []Wave               `json:"waves"`
}

type GeoStatus struct {
	Country bool `json:"country"`
	ASN     bool `json:"asn"`
}

type Wave struct {
	App  string `json:"app"`
	Bans int    `json:"bans"`
}

type Guard struct {
	runtimePath string
	dataPath    string // guard-state.json lives here, from a later task on
	now         func() time.Time

	mu         sync.RWMutex
	cfg        Config
	configured bool
}

// New loads guard.json from runtimePath when it exists.
func New(runtimePath, dataPath string, now func() time.Time) (*Guard, error) {
	g := &Guard{runtimePath: runtimePath, dataPath: dataPath, now: now}

	raw, err := os.ReadFile(filepath.Join(runtimePath, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	g.cfg, g.configured = c, true
	return g, nil
}

// SetConfig validates c, writes guard.json by rename, then swaps it in. On any error the previous config stays.
func (g *Guard) SetConfig(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := writeFileAtomic(filepath.Join(g.runtimePath, FileName), raw); err != nil {
		return err
	}
	g.cfg, g.configured = c, true
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*") // created 0600
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// Config returns the config held; treat it as read-only.
func (g *Guard) Config() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cfg
}

func (g *Guard) Configured() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.configured
}

// Status: geo, people_last_used and waves stay empty until the geo lookup and the bans fill them.
func (g *Guard) Status() Status {
	return Status{
		Version:        1,
		Configured:     g.Configured(),
		PeopleLastUsed: map[string]time.Time{},
		Waves:          []Wave{},
	}
}
