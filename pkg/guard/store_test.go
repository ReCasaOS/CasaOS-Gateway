package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestGuard(t *testing.T, dir string, c *clock) *Guard {
	t.Helper()
	g, err := New(t.TempDir(), dir, c.now)
	assert.NilError(t, err)
	return g
}

func startClock() *clock { return &clock{time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)} }

func TestBanDurationsEscalate(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)

	for i, want := range []time.Duration{time.Hour, 24 * time.Hour, 168 * time.Hour} {
		b := g.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")
		assert.Equal(t, b.Until.Sub(b.Since), want)
		assert.Equal(t, b.Strikes, i+1)
		c.add(want + time.Minute)
	}
	assert.Equal(t, len(g.Bans()), 0)

	// a fourth stays at 7 days, but after 30 quiet days the strikes are forgotten
	b := g.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")
	assert.Equal(t, b.Until.Sub(b.Since), 168*time.Hour)
	c.add(168*time.Hour + 30*24*time.Hour)
	b = g.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")
	assert.Equal(t, b.Until.Sub(b.Since), time.Hour)
	assert.Equal(t, b.Strikes, 1)
}

func TestUnbanKeepsStrikes(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)

	g.BanKey("k", "k", "a", "waf")
	_, ok := g.Banned("k")
	assert.Assert(t, ok)
	g.Unban("k")
	g.Unban("unknown") // idempotent
	_, ok = g.Banned("k")
	assert.Assert(t, !ok)

	b := g.BanKey("k", "k", "a", "waf")
	assert.Equal(t, b.Until.Sub(b.Since), 24*time.Hour)
}

func TestJournalGroupsAndTrims(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)
	e := Event{Key: "k", IP: "k", App: "jellyfin", Reason: "scan", Action: "blocked"}

	g.Record(e)
	c.add(10 * time.Second)
	g.Record(e)
	ev := g.Events("", "", 10)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Count, 2)

	c.add(61 * time.Second)
	g.Record(e)
	assert.Equal(t, len(g.Events("", "", 10)), 2)

	other := e
	other.App, other.Reason = "plex", "waf"
	g.Record(other)
	assert.Equal(t, len(g.Events("jellyfin", "scan", 5)), 2)
	assert.Equal(t, len(g.Events("", "", 3)), 3)
	assert.Equal(t, g.Events("", "", 10)[0].App, "plex") // newest first

	// older than 7 days: dropped
	c.add(8 * 24 * time.Hour)
	g.Record(e)
	assert.Equal(t, len(g.Events("", "", 10)), 1)

	// beyond 10 000 lines: oldest dropped
	for i := 0; i < 10005; i++ {
		x := e
		x.Key = fmt.Sprint("k", i)
		g.Record(x)
	}
	g.sm.Lock()
	n := len(g.journal)
	g.sm.Unlock()
	assert.Equal(t, n, 10000)
	g.sm.Lock()
	assert.Assert(t, len(g.last) <= 10000, len(g.last))
	g.sm.Unlock()
	assert.Equal(t, g.Events("", "", 1)[0].Key, "k10004")
}

func TestStoreSurvivesRestart(t *testing.T) {
	c := startClock()
	dir := filepath.Join(t.TempDir(), "gw") // does not exist yet
	g := newTestGuard(t, dir, c)

	g.BanKey("k", "k", "a", "waf")
	g.Record(Event{Key: "k", IP: "k", App: "a", Reason: "waf", Action: "banned"})
	g.NoteUse("p_1")
	assert.NilError(t, g.Flush())

	st, err := os.Stat(filepath.Join(dir, StateFileName))
	assert.NilError(t, err)
	if os.PathSeparator == '/' {
		assert.Equal(t, st.Mode().Perm(), os.FileMode(0o600))
	}

	c.add(time.Minute)
	g2 := newTestGuard(t, dir, c)
	_, ok := g2.Banned("k")
	assert.Assert(t, ok)
	assert.Equal(t, len(g2.Events("", "", 10)), 1)
	assert.Equal(t, g2.Status().PeopleLastUsed["p_1"], startClock().t)
	// strikes persisted too
	g2.Unban("k")
	assert.Equal(t, g2.BanKey("k", "k", "a", "waf").Strikes, 2)
}

func TestCorruptStateStartsEmpty(t *testing.T) {
	c := startClock()
	dir := t.TempDir()
	path := filepath.Join(dir, StateFileName)
	assert.NilError(t, os.WriteFile(path, []byte("{"), 0o600))

	g := newTestGuard(t, dir, c)
	assert.Equal(t, len(g.Bans()), 0)
	assert.NilError(t, g.Flush())
	raw, _ := os.ReadFile(path)
	assert.Assert(t, string(raw) != "{")
}

func TestWaves(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)

	for i := 0; i < 20; i++ {
		g.BanKey(fmt.Sprint("k", i), "x", "jellyfin", "scan")
	}
	assert.Equal(t, len(g.Status().Waves), 0)
	g.BanKey("k20", "x", "jellyfin", "scan")
	assert.DeepEqual(t, g.Status().Waves, []Wave{{App: "jellyfin", Bans: 21}})

	c.add(11 * time.Minute)
	assert.Equal(t, len(g.Status().Waves), 0)
}

func TestBannedKeyGroupsApartFromBlocked(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)
	e := Event{Key: "k", App: "a", Reason: "scan", Action: "blocked"}
	g.Record(e)
	c.add(10 * time.Second)
	e.Action = "banned"
	g.Record(e)
	assert.Equal(t, len(g.Events("", "", 10)), 2)
}

func TestBanKeyOnBannedKeyKeepsBan(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)
	first := g.BanKey("k", "k", "a", "waf")
	c.add(time.Minute)
	again := g.BanKey("k", "k", "a", "scan")
	assert.DeepEqual(t, again, first)
	g.Unban("k")
	assert.Equal(t, g.BanKey("k", "k", "a", "waf").Strikes, 2)
}

func TestExpiredStateDroppedOnLoad(t *testing.T) {
	c := startClock()
	dir := t.TempDir()
	g := newTestGuard(t, dir, c)
	g.BanKey("k", "k", "a", "waf")
	g.Unban("gone")
	assert.NilError(t, g.Flush())

	c.add(40 * 24 * time.Hour)
	g2 := newTestGuard(t, dir, c)
	_, ok := g2.Banned("k")
	assert.Assert(t, !ok)
	g2.sm.Lock()
	n := len(g2.strikes)
	g2.sm.Unlock()
	assert.Equal(t, n, 0)
}

func TestFlushPrunesExpired(t *testing.T) {
	c := startClock()
	dir := t.TempDir()
	g := newTestGuard(t, dir, c)
	g.BanKey("k", "k", "a", "waf")
	c.add(31*24*time.Hour + time.Hour) // ban over, strikes forgotten
	assert.NilError(t, g.Flush())

	g.sm.Lock()
	assert.Equal(t, len(g.bans), 0)
	assert.Equal(t, len(g.strikes), 0)
	g.sm.Unlock()
	raw, err := os.ReadFile(filepath.Join(dir, StateFileName))
	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(string(raw), `"key":"k"`), string(raw))
}

func TestWaveStartsPrunedWhenABanStarts(t *testing.T) {
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)
	g.BanKey("a", "a", "x", "scan")
	c.add(11 * time.Minute)
	g.BanKey("b", "b", "x", "scan")
	g.sm.Lock()
	assert.Equal(t, len(g.starts), 1)
	g.sm.Unlock()
}
