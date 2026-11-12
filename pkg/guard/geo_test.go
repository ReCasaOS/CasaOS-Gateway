package guard

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

const (
	frIP = "192.0.2.7"
	deIP = "198.51.100.7"
)

// geoDir copies the fixtures under the names DB-IP files have in production.
func geoDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	copyFixture(t, "country.mmdb", filepath.Join(dir, countryFile))
	copyFixture(t, "asn.mmdb", filepath.Join(dir, asnFile))
	return dir
}

// copyFixture replaces to by rename, as an updater must: the open reader maps the old file.
func copyFixture(t *testing.T, name, to string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	assert.NilError(t, err)
	writeAtomic(t, to, b)
}

func writeAtomic(t *testing.T, to string, b []byte) {
	t.Helper()
	assert.NilError(t, os.WriteFile(to+".new", b, 0o600))
	assert.NilError(t, os.Rename(to+".new", to))
}

func geoGuard(t *testing.T, geo string, cfg Config) (*Guard, *clock, *fakeApp, http.Handler) {
	t.Helper()
	c := startClock()
	g, err := New(t.TempDir(), t.TempDir(), geo, c.now)
	assert.NilError(t, err)
	assert.NilError(t, g.SetConfig(cfg))
	a := &fakeApp{}
	return g, c, a, g.Handler(a)
}

func TestLookupFromFixtures(t *testing.T) {
	g := OpenGeo(geoDir(t))
	cc, n, org := g.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc, "FR")
	assert.Equal(t, n, uint(3215))
	assert.Equal(t, org, "Orange")
	cc, n, org = g.Lookup(net.ParseIP("::ffff:" + deIP))
	assert.Equal(t, cc+org, "DEDeutsche Telekom")
	assert.Equal(t, n, uint(3320))
	cc, n, org = g.Lookup(net.ParseIP("203.0.113.9"))
	assert.Equal(t, cc+org, "")
	assert.Equal(t, n, uint(0))
}

func TestMissingFilesAreUnknown(t *testing.T) {
	g, err := New(t.TempDir(), t.TempDir(), t.TempDir(), startClock().now)
	assert.NilError(t, err)
	cc, n, org := g.geo.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc+org, "")
	assert.Equal(t, n, uint(0))
	assert.Equal(t, g.Status().Geo, GeoStatus{})

	g2, _ := New(t.TempDir(), t.TempDir(), geoDir(t), startClock().now)
	assert.Equal(t, g2.Status().Geo, GeoStatus{Country: true, ASN: true})
}

func TestReloadOnMtime(t *testing.T) {
	dir := geoDir(t)
	c := startClock()
	g := openGeo(dir, c.now)
	cc, _, _ := g.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc, "FR")

	path := filepath.Join(dir, countryFile)
	copyFixture(t, "country-swapped.mmdb", path)
	assert.NilError(t, os.Chtimes(path, c.now(), c.now().Add(time.Hour)))
	c.add(30 * time.Second)
	cc, _, _ = g.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc, "FR") // not looked at yet
	c.add(31 * time.Second)
	cc, _, _ = g.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc, "ES")

	// a file that no longer opens keeps the previous reader
	writeAtomic(t, path, []byte("garbage"))
	assert.NilError(t, os.Chtimes(path, c.now(), c.now().Add(2*time.Hour)))
	c.add(61 * time.Second)
	cc, _, _ = g.Lookup(net.ParseIP(frIP))
	assert.Equal(t, cc, "ES")
}

func countryCfg(mode string) Config {
	return protectedConfig(func(p *Policy) { p.Countries = Countries{Mode: mode, List: []string{"FR"}} })
}

func TestCountryBlock(t *testing.T) {
	g, _, a, h := geoGuard(t, geoDir(t), countryCfg("block"))

	w := get(h, jf, frIP, "/x", "Accept-Language", "fr")
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Equal(t, w.Body.String(), "Accès refusé.\n")
	assert.Equal(t, do(h, jf, deIP).Code, http.StatusOK)
	assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusOK) // unknown country passes
	assert.Equal(t, a.hits, 2)
	ev := g.Events("", "country", 0)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "blocked")
	assert.Equal(t, ev[0].Detail, "")
	assert.Equal(t, ev[0].Country, "FR")

	for i := 0; i < 200; i++ { // never counts toward a ban
		do(h, jf, frIP)
	}
	assert.Equal(t, len(g.Bans()), 0)
}

func TestCountryAllow(t *testing.T) {
	g, _, a, h := geoGuard(t, geoDir(t), countryCfg("allow"))

	assert.Equal(t, do(h, jf, deIP).Code, http.StatusForbidden)
	assert.Equal(t, do(h, jf, frIP).Code, http.StatusOK)
	assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusOK)
	assert.Equal(t, a.hits, 2)
	assert.Equal(t, len(g.Events("", "country", 0)), 1)

	_, _, a, h = geoGuard(t, t.TempDir(), countryCfg("allow")) // no database: pass
	assert.Equal(t, do(h, jf, deIP).Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
}

func TestEventsCarryGeo(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.Block = []string{frIP}; p.Ban.Scan404 = 1 })
	g, _, a, h := geoGuard(t, geoDir(t), cfg)

	assert.Equal(t, do(h, jf, frIP).Code, http.StatusForbidden)
	e := g.Events("", "blocklist", 0)[0]
	assert.DeepEqual(t, []any{e.Country, e.ASN, e.ASOrg}, []any{"FR", 3215, "Orange"})

	a.status = http.StatusNotFound // a scan ban on a German visitor
	do(h, jf, deIP)
	b := g.Bans()[0]
	assert.DeepEqual(t, []any{b.Country, b.ASN, b.ASOrg}, []any{"DE", 3320, "Deutsche Telekom"})
}
