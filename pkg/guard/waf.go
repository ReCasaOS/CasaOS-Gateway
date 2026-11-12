package guard

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// wafHead is the contract's directives, plus, so that file shares work under "block": PUT among the
// methods and application/octet-stream among the body types (uploads); 200002 not firing on a body
// cut at the limit (a valid body cut short is not malformed); and 901340 removed, which made Coraza
// read bodies without a parser as form fields, where binary data matches SQL and shell rules.
const (
	wafHead = `Include @coraza.conf-recommended
SecRuleEngine On
SecRequestBodyLimit 1048576
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecRuleRemoveById 200002
SecRule REQBODY_ERROR "!@eq 0" "id:9100001,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',severity:2,chain"
  SecRule INBOUND_DATA_ERROR "!@eq 1" "t:none"
Include @crs-setup.conf.example
SecAction "id:9100000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT',setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/octet-stream|'"
`
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
	d.WriteString(wafHead)
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
	d.WriteString("Include @owasp_crs/*.conf\nSecRuleRemoveById 901340\n")
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(d.String()))
}

// wafFilter is the WAF hook (step 6). It inspects the request only (headers, then the first MiB of
// the body, which the app still receives whole); a request the CRS would interrupt is journaled,
// and on "block" answered 403 and counted toward a ban.
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
		if r.Body != nil && r.Body != http.NoBody {
			var seen bytes.Buffer // what the WAF consumed, at most the body limit; the app reads it, then the rest
			_, _, _ = tx.ReadRequestBodyFrom(io.TeeReader(r.Body, &seen))
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(&seen, r.Body), r.Body}
		}
		_, _ = tx.ProcessRequestBody()
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
