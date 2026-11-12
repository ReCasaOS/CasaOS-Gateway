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

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/corazawaf/coraza/v3"
	"go.uber.org/zap"
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
	personIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`) // goes in the cookie as is: http.SetCookie must not alter it
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
		if NormalizeHost(host) != host { // the lookup is by normalised host: any other key would leave its app unfiltered
			return invalid("apps[%q]: not a normalised host (lowercase, no port, no trailing dot)", host)
		}
		if err := a.validate(fmt.Sprintf("apps[%q]", host)); err != nil {
			return err
		}
	}
	for i, person := range c.People {
		if !personIDPattern.MatchString(person.ID) {
			return invalid("people[%d].id: want 1 to 64 of A-Z a-z 0-9 _ -", i)
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
	dataPath    string // guard-state.json lives here
	now         func() time.Time

	store
	counters
	country, waf, gate hook // filled by the country filter, the WAF and the access gate; nil passes
	geo                *Geo

	mu         sync.RWMutex
	cfg        Config
	crs        coraza.WAF // built from cfg; nil when every app has its WAF off
	configured bool
	broken     bool // guard.json exists but cannot be used: shared hosts must answer 503 until a SetConfig succeeds
}

// New loads guard.json from runtimePath when it exists. A file that cannot be used does not stop
// the Gateway (it serves the dashboard too): the guard starts Broken and the error is logged.
func New(runtimePath, dataPath, geoPath string, now func() time.Time) (*Guard, error) {
	g := &Guard{runtimePath: runtimePath, dataPath: dataPath, now: now, geo: openGeo(geoPath, now)}
	g.country = g.countryFilter
	g.rates, g.rateStrikes, g.scans, g.codes, g.wafHits = map[counterKey]*rateWin{}, map[counterKey]*hits{}, map[counterKey]*hits{}, map[counterKey]*hits{}, map[counterKey]*hits{}
	g.waf = g.wafFilter
	g.gate = g.accessGate

	c, err := load(filepath.Join(runtimePath, FileName))
	if err == nil && c.Protection { // with protection off the WAF never runs
		g.crs, err = buildWAF(c.Apps)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		logger.Error("guard.json is unusable: shared apps answer 503 until the core pushes a config", zap.Error(err))
		g.broken = true
	default:
		g.cfg, g.configured = c, true
	}
	g.loadState()
	return g, nil
}

func load(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", FileName, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", FileName, err)
	}
	return c, nil
}

// Broken reports a guard.json that could not be loaded; cleared by the next successful SetConfig.
func (g *Guard) Broken() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.broken
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
	var crs coraza.WAF
	if c.Protection { // with protection off the WAF never runs
		if crs, err = buildWAF(c.Apps); err != nil { // slow (the whole CRS): outside the lock
			return err
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := writeFileAtomic(filepath.Join(g.runtimePath, FileName), raw); err != nil {
		return err
	}
	g.cfg, g.crs, g.configured, g.broken = c, crs, true, false
	return nil
}

// shortcut: no fsync before the rename, a power cut can leave an empty file (guard-state.json then loads as corrupt and drops the bans); add Sync if that matters.
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

func (g *Guard) Status() Status {
	used, waves := g.usage()
	c, a := g.geo.Loaded()
	return Status{
		Version:        1,
		Configured:     g.Configured(),
		Geo:            GeoStatus{Country: c, ASN: a},
		PeopleLastUsed: used,
		Waves:          waves,
	}
}
