package route

import (
	"encoding/json"
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
// new manifest at once.
var manifestRecheck = time.Second

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
// of an installed module the Gateway proxies: the dashboard opens it in a new tab, which sends no
// token. judged is the table's path (see tablePath), so its caller has checked it is clean.
func (g *GatewayRoute) isModulePage(method, judged string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	route := strings.TrimSuffix(judged, "/")
	if !moduleRoute.MatchString(route) || reservedModuleNames[strings.SplitN(route, "/", 3)[2]] {
		return false
	}
	proxy := g.management.GetProxy(route)
	if proxy == nil || proxy == g.management.GetProxy("/") {
		return false
	}
	return modulePages.has(route)
}

// modulePages is the gateway_route of every manifest that reads.
var modulePages = &manifestRoutes{}

type manifestRoutes struct {
	mu      sync.Mutex
	dir     string
	mtime   time.Time
	checked time.Time
	routes  map[string]bool
}

// has re-reads the manifests only when the directory's modification time changed (a manifest
// added or removed), looking at most once per manifestRecheck. A missing directory is none.
func (m *manifestRoutes) has(route string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dir != moduleManifestDir || time.Since(m.checked) >= manifestRecheck {
		m.checked = time.Now()
		info, err := os.Stat(moduleManifestDir)
		switch {
		case err != nil:
			m.dir, m.mtime, m.routes = moduleManifestDir, time.Time{}, nil
		case m.dir != moduleManifestDir || !info.ModTime().Equal(m.mtime):
			m.dir, m.mtime, m.routes = moduleManifestDir, info.ModTime(), readManifestRoutes(moduleManifestDir)
		}
	}
	return m.routes[route]
}

// readManifestRoutes reads every *.json of dir; a file that does not read, or whose gateway_route
// is not a string of the right shape, is skipped.
func readManifestRoutes(dir string) map[string]bool {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	routes := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var manifest map[string]any
		if json.Unmarshal(raw, &manifest) != nil {
			continue
		}
		if r, ok := manifest["gateway_route"].(string); ok && moduleRoute.MatchString(r) {
			routes[r] = true
		}
	}
	return routes
}
