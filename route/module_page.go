package route

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// moduleManifestDir holds the manifests the installer copies, root-owned; a variable so a test can
// point it elsewhere.
var moduleManifestDir = "/etc/casaos/modules"

// manifestRecheck is how often the directory is looked at again; a variable so a test can see a
// change at once.
var manifestRecheck = time.Second

// Bounds on the manifests, so a stray file can neither hang nor bloat the gateway.
const (
	maxManifests     = 256
	maxManifestBytes = 64 << 10
)

// moduleRoute is the shape of a module's gateway_route.
var moduleRoute = regexp.MustCompile(`^/v[0-9]+/[a-z][a-z0-9_]{0,31}$`)

// reservedModuleNames are the core's and the distribution's own routes (CasaOS-UI moduleCards.js
// RESERVED, and the installer's docs/modules.md): a stray manifest must never open one.
var reservedModuleNames = map[string]bool{
	"sys": true, "users": true, "file": true, "folder": true, "port": true, "batch": true, "image": true,
	"samba": true, "notify": true, "driver": true, "cloud": true, "recover": true, "other": true, "zt": true,
	"fleet": true, "share": true, "test": true, "app_management": true, "message_bus": true,
	"local_storage": true, "gateway": true, "casaos": true, "container": true, "disks": true,
	"storage": true, "usb": true, "health": true, "apps": true,
}

// isModulePage is a GET or HEAD of a module's page, R or R/ exactly, where R is the gateway_route
// of an installed module and a route key of the Gateway itself (not merely under one): the
// dashboard opens it in a new tab, which sends no token. Never an upgrade, which would open a
// channel rather than a page. judged is the table's path (see tablePath), so its caller has
// checked it is clean.
func (g *GatewayRoute) isModulePage(r *http.Request, judged string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead || r.Header.Get("Upgrade") != "" {
		return false
	}
	route := strings.TrimSuffix(judged, "/")
	if !moduleRoute.MatchString(route) || reservedModuleNames[strings.SplitN(route, "/", 3)[2]] {
		return false
	}
	return g.management.HasRoute(route) && modulePages.has(route)
}

// modulePages is the gateway_route of every manifest that reads.
var modulePages = &manifestRoutes{}

type manifestRoutes struct {
	mu      sync.Mutex
	dir     string
	stamp   string // the directory's and each entry's size and mtime, as last read
	checked time.Time
	routes  map[string]bool
}

// has looks at the directory at most once per manifestRecheck and re-reads the manifests only when
// the directory or an entry changed. The look happens outside the lock: meanwhile other requests
// get the last set.
func (m *manifestRoutes) has(route string) bool {
	m.mu.Lock()
	dir, stamp := moduleManifestDir, m.stamp
	due := m.dir != dir || time.Since(m.checked) >= manifestRecheck
	if due {
		m.checked = time.Now()
	}
	m.mu.Unlock()

	if due {
		newStamp, routes, changed := readManifestRoutes(dir, stamp)
		m.mu.Lock()
		if changed || m.dir != dir {
			m.dir, m.stamp, m.routes = dir, newStamp, routes
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routes[route]
}

// readManifestRoutes lists at most maxManifests entries of dir and, unless their stamp is still
// stamp, reads the *.json among them (see manifestRoute). A directory that does not read is none.
func readManifestRoutes(dir, stamp string) (string, map[string]bool, bool) {
	d, err := os.Open(dir)
	if err != nil {
		return "", nil, stamp != ""
	}
	defer d.Close()
	info, err := d.Stat()
	if err != nil {
		return "", nil, stamp != ""
	}
	entries, _ := d.ReadDir(maxManifests)

	// an overwrite in place leaves the directory's mtime alone, so each entry counts too
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d\n", info.ModTime().UnixNano())
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			fmt.Fprintf(&sb, "%s %d %d\n", e.Name(), fi.Size(), fi.ModTime().UnixNano())
		}
	}
	if sb.String() == stamp {
		return stamp, nil, false
	}

	routes := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if r, ok := manifestRoute(filepath.Join(dir, e.Name())); ok {
			routes[r] = true
		}
	}
	return sb.String(), routes, true
}

// manifestRoute is the gateway_route of one manifest. A file that does not read, is not a regular
// file (a symlink, a FIFO), is larger than maxManifestBytes, or whose gateway_route is not a string
// of the right shape, has none. The file is judged through its own handle, opened without following
// a symlink or waiting on a FIFO, so it cannot be swapped between the check and the read.
func manifestRoute(name string) (string, bool) {
	f, err := os.OpenFile(name, os.O_RDONLY|manifestOpenFlags, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil || len(raw) > maxManifestBytes {
		return "", false
	}
	var manifest map[string]any
	if json.Unmarshal(raw, &manifest) != nil {
		return "", false
	}
	r, ok := manifest["gateway_route"].(string)
	return r, ok && moduleRoute.MatchString(r)
}
