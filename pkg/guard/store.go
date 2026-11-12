package guard

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
)

// StateFileName holds bans, strikes, the journal and the last use of each person, in the data path.
const StateFileName = "guard-state.json"

const (
	journalMaxAge   = 7 * 24 * time.Hour
	journalMaxLines = 10000
	groupWindow     = 60 * time.Second
	strikeMemory    = 30 * 24 * time.Hour
	waveWindow      = 10 * time.Minute
	waveBans        = 20 // more than this many bans on one app in the window is a wave
)

// Event is one line of the journal.
type Event struct {
	Time    time.Time `json:"time"`
	IP      string    `json:"ip"`
	Key     string    `json:"key"`
	Country string    `json:"country"`
	ASN     int       `json:"asn"`
	ASOrg   string    `json:"as_org"`
	App     string    `json:"app"`
	Path    string    `json:"path"`
	Reason  string    `json:"reason"`
	Rule    int       `json:"rule,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Action  string    `json:"action"`
	Count   int       `json:"count"`
}

// Ban is an active ban.
type Ban struct {
	Key     string    `json:"key"`
	IP      string    `json:"ip"`
	Country string    `json:"country"`
	ASN     int       `json:"asn"`
	ASOrg   string    `json:"as_org"`
	App     string    `json:"app"`
	Reason  string    `json:"reason"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Strikes int       `json:"strikes"`
}

type strike struct {
	Count int       `json:"count"`
	Last  time.Time `json:"last"` // when the last ban ended or was lifted
}

type groupKey struct {
	key, app, reason, action string
	rule                     int
}

type waveStart struct {
	app string
	at  time.Time
}

// store is in memory under sm; the caller (main) runs Flush every 30 s and on shutdown.
type store struct {
	sm      sync.RWMutex
	flushMu sync.Mutex // one Flush at a time; the write happens outside sm
	dirty   bool
	journal []*Event // oldest first
	last    map[groupKey]*Event
	bans    map[string]Ban
	strikes map[string]strike
	used    map[string]time.Time
	starts  []waveStart // shortcut: waves are forgotten at restart, they last 10 minutes
}

type stateFile struct {
	Events  []*Event             `json:"events"`
	Bans    []Ban                `json:"bans"`
	Strikes map[string]strike    `json:"strikes"`
	Used    map[string]time.Time `json:"people_last_used"`
}

func (s *store) reset() {
	s.journal, s.last = nil, map[groupKey]*Event{}
	s.bans, s.strikes, s.used = map[string]Ban{}, map[string]strike{}, map[string]time.Time{}
	s.starts = nil
}

// loadState reads guard-state.json. A file that cannot be read starts empty (and is replaced at the next Flush).
func (g *Guard) loadState() {
	g.sm.Lock()
	defer g.sm.Unlock()
	g.reset()

	raw, err := os.ReadFile(filepath.Join(g.dataPath, StateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var st stateFile
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	if err != nil {
		logger.Error("guard-state.json is unusable: starting empty", zap.Error(err))
		g.dirty = true
		return
	}
	now := g.now()
	for _, e := range st.Events {
		if e != nil {
			g.journal = append(g.journal, e)
			g.last[groupKey{e.Key, e.App, e.Reason, e.Action, e.Rule}] = e
		}
	}
	g.trim(now)
	for _, b := range st.Bans {
		if b.Until.After(now) {
			g.bans[b.Key] = b
		}
	}
	for k, v := range st.Strikes {
		g.strikes[k] = v
	}
	g.pruneStrikes(now)
	for k, v := range st.Used {
		g.used[k] = v
	}
}

// pruneStrikes forgets the strikes whose 30 days are over.
func (g *Guard) pruneStrikes(now time.Time) {
	for k, v := range g.strikes {
		if now.Sub(v.Last) >= strikeMemory {
			delete(g.strikes, k)
		}
	}
}

// Flush writes guard-state.json by rename when something changed since the last Flush. The state
// is copied under the lock; marshalling and writing happen outside it.
func (g *Guard) Flush() error {
	g.flushMu.Lock()
	defer g.flushMu.Unlock()

	g.sm.Lock()
	if !g.dirty {
		g.sm.Unlock()
		return nil
	}
	now := g.now()
	g.pruneStrikes(now)
	for k, b := range g.bans {
		if !b.Until.After(now) {
			delete(g.bans, k)
		}
	}
	st := stateFile{Events: make([]*Event, len(g.journal)), Bans: []Ban{}, Strikes: map[string]strike{}, Used: map[string]time.Time{}}
	for i, e := range g.journal {
		c := *e
		st.Events[i] = &c
	}
	for _, b := range g.bans {
		st.Bans = append(st.Bans, b)
	}
	for k, v := range g.strikes {
		st.Strikes[k] = v
	}
	for k, v := range g.used {
		st.Used[k] = v
	}
	g.dirty = false
	g.sm.Unlock()

	err := g.writeState(st)
	if err != nil {
		g.sm.Lock()
		g.dirty = true
		g.sm.Unlock()
	}
	return err
}

func (g *Guard) writeState(st stateFile) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.dataPath, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(g.dataPath, StateFileName), raw)
}

// trim drops lines older than 7 days, then the oldest beyond 10 000.
func (g *Guard) trim(now time.Time) {
	i := 0
	for i < len(g.journal) && now.Sub(g.journal[i].Time) > journalMaxAge {
		i++
	}
	if n := len(g.journal) - i - journalMaxLines; n > 0 {
		i += n
	}
	for _, e := range g.journal[:i] {
		if gk := (groupKey{e.Key, e.App, e.Reason, e.Action, e.Rule}); g.last[gk] == e {
			delete(g.last, gk)
		}
	}
	if i > 0 {
		g.journal = append([]*Event(nil), g.journal[i:]...)
	}
}

// Record adds a line to the journal, or increments the count of the line it repeats: same key,
// app, reason and rule within 60 s of that line's first event.
func (g *Guard) Record(e Event) {
	if e.Country == "" && e.ASN == 0 && e.ASOrg == "" {
		e.Country, e.ASN, e.ASOrg = g.geo.lookupIP(e.IP)
	}
	g.sm.Lock()
	defer g.sm.Unlock()
	now := g.now()
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.Count < 1 {
		e.Count = 1
	}
	g.dirty = true
	gk := groupKey{e.Key, e.App, e.Reason, e.Action, e.Rule}
	if p := g.last[gk]; p != nil && e.Time.Sub(p.Time) < groupWindow {
		p.Count += e.Count
		return
	}
	g.journal = append(g.journal, &e)
	g.last[gk] = &e
	g.trim(now)
}

// Events returns the journal newest first, filtered by app and reason when not empty; limit defaults to 200, max 1000.
func (g *Guard) Events(app, reason string, limit int) []Event {
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 1000)
	g.sm.Lock()
	defer g.sm.Unlock()
	out := []Event{}
	for i := len(g.journal) - 1; i >= 0 && len(out) < limit; i-- {
		e := g.journal[i]
		if (app == "" || e.App == app) && (reason == "" || e.Reason == reason) {
			out = append(out, *e)
		}
	}
	return out
}

// Banned returns the active ban of key.
func (g *Guard) Banned(key string) (Ban, bool) {
	g.sm.RLock()
	defer g.sm.RUnlock()
	b, ok := g.bans[key]
	if ok && !b.Until.After(g.now()) {
		return Ban{}, false // Bans() removes it
	}
	return b, ok
}

// BanKey bans key for 1 h, 24 h, then 7 days, by strike; strikes are forgotten 30 days after the
// last ban ended. A key already banned keeps its ban.
func (g *Guard) BanKey(key, ip, app, reason string) Ban {
	cc, asn, org := g.geo.lookupIP(ip)
	g.sm.Lock()
	defer g.sm.Unlock()
	now := g.now()
	if b, ok := g.bans[key]; ok && b.Until.After(now) {
		return b
	}
	s := g.strikes[key]
	if now.Sub(s.Last) >= strikeMemory {
		s.Count = 0
	}
	s.Count++
	d := 7 * 24 * time.Hour
	switch s.Count {
	case 1:
		d = time.Hour
	case 2:
		d = 24 * time.Hour
	}
	b := Ban{Key: key, IP: ip, Country: cc, ASN: asn, ASOrg: org, App: app, Reason: reason, Since: now, Until: now.Add(d), Strikes: s.Count}
	s.Last = b.Until
	g.strikes[key] = s
	g.bans[key] = b
	cut := now.Add(-waveWindow)
	keep := g.starts[:0]
	for _, w := range g.starts {
		if w.at.After(cut) {
			keep = append(keep, w)
		}
	}
	g.starts = append(keep, waveStart{app, now})
	g.dirty = true
	return b
}

// Unban lifts the ban now (idempotent); the strikes are kept.
func (g *Guard) Unban(key string) {
	g.sm.Lock()
	defer g.sm.Unlock()
	if _, ok := g.bans[key]; !ok {
		return
	}
	delete(g.bans, key)
	s := g.strikes[key]
	s.Last = g.now()
	g.strikes[key] = s
	g.dirty = true
}

// Bans returns the active bans, newest first.
func (g *Guard) Bans() []Ban {
	g.sm.Lock()
	defer g.sm.Unlock()
	now := g.now()
	out := []Ban{}
	for k, b := range g.bans {
		if b.Until.After(now) {
			out = append(out, b)
		} else {
			delete(g.bans, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out
}

// NoteUse records that a person's code was just used.
func (g *Guard) NoteUse(personID string) {
	g.sm.Lock()
	defer g.sm.Unlock()
	g.used[personID] = g.now()
	g.dirty = true
}

// usage returns a copy of the last use of each person, and the apps with a wave of bans.
func (g *Guard) usage() (map[string]time.Time, []Wave) {
	g.sm.Lock()
	defer g.sm.Unlock()
	used := make(map[string]time.Time, len(g.used))
	for k, v := range g.used {
		used[k] = v
	}
	cut := g.now().Add(-waveWindow)
	n := map[string]int{}
	keep := g.starts[:0]
	for _, w := range g.starts {
		if w.at.After(cut) {
			keep = append(keep, w)
			n[w.app]++
		}
	}
	g.starts = keep
	waves := []Wave{}
	for app, c := range n {
		if c > waveBans {
			waves = append(waves, Wave{App: app, Bans: c})
		}
	}
	sort.Slice(waves, func(i, j int) bool { return waves[i].App < waves[j].App })
	return used, waves
}
