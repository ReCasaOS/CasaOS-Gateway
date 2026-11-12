package guard

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// wafHead departs from stock CRS for shared apps: 64 KiB of body inspected (CPU), PUT PATCH DELETE + WebDAV allowed, 920420 off (any upload type), 9100001 for 200002 (a body cut at the limit is not malformed), 901340 off (binary is not form fields).
const (
	wafHead = `Include @coraza.conf-recommended
SecRuleEngine On
SecRequestBodyLimit %[1]d
SecRequestBodyNoFilesLimit %[1]d
SecRequestBodyInMemoryLimit %[1]d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecRuleRemoveById 200002
SecRule REQBODY_ERROR "!@eq 0" "id:9100001,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',severity:2,chain"
  SecRule INBOUND_DATA_ERROR "!@eq 1" "t:none"
Include @crs-setup.conf.example
SecAction "id:9100000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT'"
`
	wafBodyLimit  = 64 << 10 // bytes of a body inspected
	inspectSlots  = 2        // body inspections at once for the whole box; 1 per key
	inspectWait   = 2 * time.Second
	hostRuleFirst = 9100100 // per-host rules: 9100100 to 9199999
	hostRuleLast  = 9199999
	detailMax     = 200
)

// hostChars keeps a host from breaking the directive it goes in; Validate only checks it is normalised.
var hostChars = regexp.MustCompile(`^[a-z0-9._-]+$`)

// buildWAF compiles one WAF for every host: the CRS, then one phase-1 rule per host with rules_off
// that removes them for that host's transactions. nil when no app has its WAF on (no CRS loaded).
// The mode (observe or block) is applied in Go on the interruption, see wafFilter.
func buildWAF(apps map[string]AppConfig) (coraza.WAF, error) {
	var hosts []string
	for h, a := range apps {
		if a.Policy.WAF != "off" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	sort.Strings(hosts) // stable rule ids
	var d strings.Builder
	fmt.Fprintf(&d, wafHead, wafBodyLimit)
	for i, h := range hosts {
		off := apps[h].Policy.RulesOff
		if len(off) == 0 {
			continue
		}
		id := hostRuleFirst + i
		if !hostChars.MatchString(h) || id > hostRuleLast {
			return nil, invalid("apps[%q]: not a host name the WAF can match", h)
		}
		fmt.Fprintf(&d, `SecRule REQUEST_HEADERS:Host "@streq %s" "id:%d,phase:1,pass,nolog,t:none`, h, id)
		for _, r := range off {
			fmt.Fprintf(&d, ",ctl:ruleRemoveById=%d", r)
		}
		d.WriteString("\"\n")
	}
	d.WriteString("Include @owasp_crs/*.conf\nSecRuleRemoveById 901340 920420\n")
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(d.String()))
}

// wafFilter is the WAF hook (step 6). It inspects the request only (headers, then the first 64 KiB of
// a body Coraza parses, which the app still receives whole); a request the CRS would interrupt is
// journaled, and on "block" answered 403 and counted toward a ban. Body inspections are capped (see
// slots): one that gets no slot within 2 s is answered 503.
func (g *Guard) wafFilter(w http.ResponseWriter, r *http.Request, app AppConfig) bool {
	mode := app.Policy.WAF
	if mode == "off" || (app.Access == "code" && r.URL.Path == EntryPath) { // the gate's own form
		return false
	}
	g.mu.RLock()
	waf := g.crs
	g.mu.RUnlock()
	if waf == nil {
		return false
	}

	key, ip := Key(r.RemoteAddr)
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(ip, 0, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	h := r.Header.Clone()
	takeCookie(&http.Request{Header: h}) // our session cookie: a signature can hold "--"
	for k, vs := range h {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.AddRequestHeader("Host", NormalizeHost(r.Host)) // what the per-host rules match
	for _, te := range r.TransferEncoding {            // removed by net/http; rules about smuggling read it
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if tx.ProcessRequestHeaders() == nil {
		// Only a body Coraza parses (form, multipart, JSON, XML) is worth reading: the others reach no rule.
		parsed := tx.(plugintypes.TransactionState).Variables().RequestBodyProcessor().Get() != ""
		if parsed && r.Body != nil && r.Body != http.NoBody {
			// read before taking a slot, so a slow client cannot hold one
			seen, _ := io.ReadAll(io.LimitReader(r.Body, wafBodyLimit))
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(seen), r.Body), r.Body} // the app reads what the WAF read, then the rest
			release, ok := g.slots.take(key, g.inspectWait)
			if !ok { // never pass uninspected; not counted toward a ban
				g.Record(Event{IP: ip, Key: key, App: app.App, Path: eventPath(r), Reason: "waf", Detail: "inspection busy", Action: "blocked"})
				deny(w, r, http.StatusServiceUnavailable)
				return true
			}
			if g.inspecting != nil {
				g.inspecting()
			}
			_, _, _ = tx.ReadRequestBodyFrom(bytes.NewReader(seen))
			_, _ = tx.ProcessRequestBody()
			release()
		} else {
			_, _ = tx.ProcessRequestBody()
		}
	}
	it := tx.Interruption()
	if it == nil {
		return false
	}

	rule, detail := decidingRule(tx.MatchedRules(), it.RuleID)
	ev := Event{IP: ip, Key: key, App: app.App, Path: eventPath(r), Reason: "waf", Rule: rule, Detail: detail, Action: "observed"}
	if mode != "block" {
		g.Record(ev)
		return false
	}
	ck := counterKey{key, app.App}
	g.cm.Lock()
	now := g.now()
	g.sweep(now)
	ban := g.note(g.wafHits, ck, now, app.Policy.Ban.WAFWindowS) >= app.Policy.Ban.WAFHits
	if ban {
		delete(g.wafHits, ck)
	}
	g.cm.Unlock()
	ev.Action = "blocked"
	if ban {
		g.BanKey(key, ip, app.App, "waf")
		ev.Action = "banned"
	}
	g.Record(ev)
	deny(w, r, http.StatusForbidden)
	return true
}

// slots caps the body inspections running at once (CPU): inspectSlots for the box, one per key.
type slots struct {
	box  chan struct{}
	mu   sync.Mutex
	keys map[string]*keySlot // only keys with a request holding or waiting for their slot
}

type keySlot struct {
	ch    chan struct{}
	users int
}

func newSlots(n int) *slots { return &slots{box: make(chan struct{}, n), keys: map[string]*keySlot{}} }

// take waits up to wait for the key's slot, then one of the box's; release gives both back.
func (s *slots) take(key string, wait time.Duration) (release func(), ok bool) {
	s.mu.Lock()
	k := s.keys[key]
	if k == nil {
		k = &keySlot{ch: make(chan struct{}, 1)}
		s.keys[key] = k
	}
	k.users++
	s.mu.Unlock()
	leave := func() {
		s.mu.Lock()
		if k.users--; k.users == 0 {
			delete(s.keys, key)
		}
		s.mu.Unlock()
	}

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case k.ch <- struct{}{}:
	case <-t.C:
		leave()
		return nil, false
	}
	select {
	case s.box <- struct{}{}:
	case <-t.C:
		<-k.ch
		leave()
		return nil, false
	}
	return func() { <-s.box; <-k.ch; leave() }, true
}

// decidingRule is the rule that denied, or when that is the anomaly score total (949xxx) the first
// matched rule with a severity; with its message, never the matched data.
func decidingRule(matched []types.MatchedRule, interrupting int) (int, string) {
	var pick types.RuleMetadata
	for _, m := range matched {
		md := m.Rule()
		if interrupting/1000 == 949 && md.Severity() != types.RuleSeverityUnset && md.ID()/1000 != 949 {
			pick = md
			break
		}
		if md.ID() == interrupting && pick == nil {
			pick = md
		}
	}
	if pick == nil {
		return interrupting, ""
	}
	return pick.ID(), ruleMsg(pick.Raw())
}

// ruleMsg is the msg of a rule as written, cut before its first macro (CRS puts matched values in
// some, e.g. "(%{MATCHED_VAR})"), at most 200 bytes.
func ruleMsg(raw string) string {
	_, msg, ok := strings.Cut(raw, "msg:'")
	if !ok {
		return ""
	}
	msg, _, _ = strings.Cut(msg, "'")
	msg, _, _ = strings.Cut(msg, "%{")
	msg = strings.TrimRight(msg, " (")
	if len(msg) > detailMax {
		msg = msg[:detailMax]
	}
	return msg
}
