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
	headMax       = 16 << 10 // bytes of URI and headers inspected; a larger head is not
	headFree      = 4 << 10  // a head above this costs CPU like a body: it takes a slot
	partsMax      = 100      // cookie pairs, and query args, inspected
	inspectSlots  = 2        // inspections at once for the whole box; 1 per key
	inspectWait   = 2 * time.Second
	hostRuleFirst = 9100100 // per-host rules: 9100100 to 9199999
	hostRuleLast  = 9199999
	detailMax     = 200
)

// hostChars keeps a host from breaking the directive it goes in; Validate only checks it is normalised.
var hostChars = regexp.MustCompile(`^[a-z0-9._-]+$`)

// wafRules are the directives of one WAF for every host: the CRS, then one phase-1 rule per host
// with rules_off that removes them for that host's transactions. "" when no app has its WAF on (no
// CRS loaded). The mode (observe or block) is applied in Go on the interruption, see wafFilter.
func wafRules(apps map[string]AppConfig) (string, error) {
	var hosts []string
	for h, a := range apps {
		if a.Policy.WAF != "off" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return "", nil
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
			return "", invalid("apps[%q]: not a host name the WAF can match", h)
		}
		fmt.Fprintf(&d, `SecRule REQUEST_HEADERS:Host "@streq %s" "id:%d,phase:1,pass,nolog,t:none`, h, id)
		for _, r := range off {
			fmt.Fprintf(&d, ",ctl:ruleRemoveById=%d", r)
		}
		d.WriteString("\"\n")
	}
	d.WriteString("Include @owasp_crs/*.conf\nSecRuleRemoveById 901340 920420\n")
	return d.String(), nil
}

// newWAF compiles rules (slow: the whole CRS); nil for "".
func newWAF(rules string) (coraza.WAF, error) {
	if rules == "" {
		return nil, nil
	}
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(rules))
}

// headSize is what the CRS would read of r's head: bytes of URI and headers, cookie pairs and query args.
func headSize(r *http.Request) (size, cookies, args int) {
	size = len(r.URL.RequestURI())
	for k, vs := range r.Header {
		for _, v := range vs {
			size += len(k) + len(v)
			if k == "Cookie" {
				cookies += strings.Count(v, ";") + 1
			}
		}
	}
	if q := r.URL.RawQuery; q != "" {
		args = strings.Count(q, "&") + 1
	}
	return size, cookies, args
}

// wafFilter is the WAF hook (step 6). It inspects the request only (headers, then the first 64 KiB of
// a body Coraza parses, which the app still receives whole); a request the CRS would interrupt is
// journaled, and on "block" answered 403 and counted toward a ban. A head over 16 KiB, 100 cookies or
// 100 query args is not inspected: 431 on "block", passed on "observe". Inspections of bodies and of
// heads over 4 KiB are capped (see slots): one that gets no slot within 2 s is answered 503 on
// "block" and passes on "observe".
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
	head, cookies, args := headSize(r)
	if head > headMax || cookies > partsMax || args > partsMax {
		return g.unchecked(w, r, app, "request too large to inspect", http.StatusRequestHeaderFieldsTooLarge)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(ip, 0, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	h := r.Header.Clone()
	takeCookie(&http.Request{Header: h}) // our session cookie: a signature can hold "--"
	h.Del("Host")                        // HTTP/2 keeps a client "host" beside :authority; only r.Host is the app's
	for k, vs := range h {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.AddRequestHeader("Host", NormalizeHost(r.Host)) // what the per-host rules match
	for _, te := range r.TransferEncoding {            // removed by net/http; rules about smuggling read it
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	var held func() // the slot this inspection holds; given back on return, a panic included
	defer func() {
		if held != nil {
			held()
		}
	}()
	take := func() (ok bool) {
		held, ok = g.slots.take(key, g.inspectWait)
		return ok
	}
	// A head over 4 KiB costs CPU like a body: the CRS reads its cookies and args in phase 2.
	if head > headFree && !take() {
		return g.unchecked(w, r, app, "inspection busy", http.StatusServiceUnavailable)
	}
	if tx.ProcessRequestHeaders() == nil {
		var err error
		// Only a body Coraza parses (form, multipart, JSON, XML) is worth reading: the others reach no rule.
		parsed := tx.(plugintypes.TransactionState).Variables().RequestBodyProcessor().Get() != ""
		if parsed && r.Body != nil && r.Body != http.NoBody {
			// read without a slot, so a slow client cannot hold one
			if held != nil {
				held()
				held = nil
			}
			var seen []byte
			seen, err = io.ReadAll(io.LimitReader(r.Body, wafBodyLimit))
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(seen), r.Body), r.Body} // the app reads what the WAF read, then the rest
			if err == nil {
				if !take() {
					return g.unchecked(w, r, app, "inspection busy", http.StatusServiceUnavailable)
				}
				if g.inspecting != nil {
					g.inspecting()
				}
				if _, _, err = tx.ReadRequestBodyFrom(bytes.NewReader(seen)); err == nil {
					_, err = tx.ProcessRequestBody()
				}
			}
		} else {
			if held != nil && g.inspecting != nil {
				g.inspecting()
			}
			_, err = tx.ProcessRequestBody()
		}
		if err != nil {
			return g.unchecked(w, r, app, "inspection error", http.StatusForbidden)
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

// unchecked answers a request the WAF could not inspect: "block" refuses it with code, "observe" lets
// it pass; one event either way, never counted toward a ban.
func (g *Guard) unchecked(w http.ResponseWriter, r *http.Request, app AppConfig, detail string, code int) bool {
	key, ip := Key(r.RemoteAddr)
	ev := Event{IP: ip, Key: key, App: app.App, Path: eventPath(r), Reason: "waf", Detail: detail, Action: "observed"}
	if app.Policy.WAF != "block" {
		g.Record(ev)
		return false
	}
	ev.Action = "blocked"
	g.Record(ev)
	deny(w, r, code)
	return true
}

// slots caps the costly inspections running at once (CPU): inspectSlots for the box, one per key.
type slots struct {
	box    chan struct{}
	mu     sync.Mutex
	keys   map[string]*keySlot // only keys with a request holding or waiting for their slot
	queued func()              // test hook, run when a request starts waiting; nil in production
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
	if s.queued != nil {
		s.queued()
	}
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

// decidingRule is the rule that denied; when that is the anomaly score total (949xxx), the matched
// rule of highest severity (the first among equals) other than 949xxx. With its message, never the
// matched data.
func decidingRule(matched []types.MatchedRule, interrupting int) (int, string) {
	var pick, denier types.RuleMetadata
	for _, m := range matched {
		md := m.Rule()
		if md.ID() == interrupting && denier == nil {
			denier = md
		}
		sev := md.Severity()
		if sev != types.RuleSeverityUnset && md.ID()/1000 != 949 && (pick == nil || sev < pick.Severity()) { // 0 is emergency
			pick = md
		}
	}
	if interrupting/1000 != 949 || pick == nil {
		pick = denier
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
