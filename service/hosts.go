package service

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const HostsFile = "hosts.json" // {"<host>":"<target>"}, same shape and mode as routes.json

type HostRoute struct {
	Host   string `json:"host"`
	Target string `json:"target"`
}

var (
	ErrBadHost   = errors.New("invalid host")
	ErrBadTarget = errors.New("invalid target")
)

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// NormalizeHost lowercases h, strips a port and a trailing dot. "" stays "".
func NormalizeHost(h string) string {
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func parseHostTarget(target string) (*url.URL, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, ErrBadTarget
	}
	return u, nil
}

func newHostProxy(target *url.URL) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.Host = r.In.Host // the app sees its public name
		r.SetXForwarded()      // For = client alone, Host, Proto — what the client sent is dropped
	}}
	if target.Scheme == "https" { // shortcut: the app is on this box, its certificate is its own business; revisit if a target ever leaves loopback
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		p.Transport = tr
	}
	return p
}

// SetHost validates r, (re)places the route and saves hosts.json.
func (g *Management) SetHost(r HostRoute) error {
	host := NormalizeHost(r.Host)
	if len(host) > 253 || !hostPattern.MatchString(host) {
		return ErrBadHost
	}
	target, err := parseHostTarget(r.Target)
	if err != nil {
		return err
	}

	g.hostMu.Lock()
	defer g.hostMu.Unlock()
	g.hostTargetMap[host] = r.Target
	g.hostProxyMap[host] = newHostProxy(target)
	return g.saveHosts()
}

// DeleteHost is idempotent.
func (g *Management) DeleteHost(host string) error {
	host = NormalizeHost(host)

	g.hostMu.Lock()
	defer g.hostMu.Unlock()
	delete(g.hostTargetMap, host)
	delete(g.hostProxyMap, host)
	return g.saveHosts()
}

// GetHosts returns the routes sorted by host; never nil.
func (g *Management) GetHosts() []HostRoute {
	g.hostMu.RLock()
	defer g.hostMu.RUnlock()

	routes := make([]HostRoute, 0, len(g.hostTargetMap))
	for host, target := range g.hostTargetMap {
		routes = append(routes, HostRoute{Host: host, Target: target})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Host < routes[j].Host })
	return routes
}

// GetHostProxy returns nil when no route matches host.
func (g *Management) GetHostProxy(host string) *httputil.ReverseProxy {
	g.hostMu.RLock()
	defer g.hostMu.RUnlock()
	return g.hostProxyMap[NormalizeHost(host)]
}

// saveHosts must be called with hostMu held for writing.
func (g *Management) saveHosts() error {
	return savePathTargetMapTo(filepath.Join(g.State.GetRuntimePath(), HostsFile), g.hostTargetMap)
}
