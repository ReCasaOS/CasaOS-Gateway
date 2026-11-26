package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"gotest.tools/v3/assert"
)

// withManifests points the gateway at a directory holding these manifests, by file name.
func withManifests(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		assert.NilError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	saved := moduleManifestDir
	t.Cleanup(func() { moduleManifestDir = saved })
	moduleManifestDir = dir
	return dir
}

// newModuleEnv is the usual env plus route keys laid out per service, as on a box: a module's page
// needs its own key, a key it merely sits under is not enough.
func newModuleEnv(t *testing.T) *readOnlyEnv {
	t.Helper()
	env := newReadOnlyEnv(t)
	var backend string
	for _, r := range env.mgmt.GetRoutes() {
		if r.Path == "/v1" {
			backend = r.Target
		}
	}
	for _, p := range []string{"/v1/sys", "/v1/wake_on_lan", "/v2/mcp", "/v2/app_management"} {
		assert.NilError(t, env.mgmt.CreateRoute(&model.Route{Path: p, Target: backend}))
	}
	return env
}

const wakeOnLan = `{"name":"wake_on_lan","gateway_route":"/v1/wake_on_lan"}`

func TestModulePageOpensWithoutToken(t *testing.T) {
	env := newModuleEnv(t)
	withManifests(t, map[string]string{"wake_on_lan.json": wakeOnLan})
	for _, row := range []struct{ method, path string }{
		{"GET", "/v1/wake_on_lan/"}, {"GET", "/v1/wake_on_lan"}, {"HEAD", "/v1/wake_on_lan/"}, {"HEAD", "/v1/wake_on_lan"},
		{"GET", "/v1/wake_on_lan/?x=1"},
	} {
		before := len(env.hits.list())
		assert.Equal(t, env.call(t, row.method, row.path, nil), 200, row.method+" "+row.path)
		assert.Equal(t, len(env.hits.list()), before+1) // it reached the module
	}
	// anything deeper, another method, an upgrade, or a path not in its plain form is judged as before
	before := len(env.hits.list())
	for _, row := range []struct {
		method, path string
		header       map[string]string
		want         int
	}{
		{"GET", "/v1/wake_on_lan/devices", nil, 401}, {"GET", "/v1/wake_on_lan/card", nil, 401},
		{"GET", "/v1/wake_on_lan/x/", nil, 401}, {"POST", "/v1/wake_on_lan/", nil, 401},
		{"PUT", "/v1/wake_on_lan", nil, 401}, {"OPTIONS", "/v1/wake_on_lan/", nil, 401},
		{"GET", "/v1/wake_on_lan//", nil, 307}, // the mux cleans it first, as on any path
		{"GET", "/v1/wake_on_lan/%2e%2e/", nil, 401}, {"GET", "/v1/wake%5Fon_lan/", nil, 401},
		{"GET", "/v1/wake_on_lanx/", nil, 401}, {"GET", "/v1/wake_on/", nil, 401},
		{"GET", "/v1/wake_on_lan/", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, 401},
		{"GET", "/v1/wake_on_lan", map[string]string{"Upgrade": "h2c"}, 401},
	} {
		assert.Equal(t, env.call(t, row.method, row.path, row.header), row.want, row.method+" "+row.path)
	}
	// the gate itself refuses the doubled slash too, should a request reach it uncleaned
	reached := false
	gate := NewGatewayRoute(env.mgmt).closedForUsers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest("GET", "/v1/wake_on_lan//", nil))
	assert.Equal(t, w.Code, 401)
	assert.Assert(t, !reached)
	assert.Equal(t, len(env.hits.list()), before)
}

// A token on the page, whatever it is, never blocks it.
func TestModulePageWithToken(t *testing.T) {
	env := newModuleEnv(t)
	withManifests(t, map[string]string{"wake_on_lan.json": wakeOnLan})
	signKey, _ := testKeys(t)
	expired, err := jwt.GenerateToken("someone", signKey, userID, jwt.AccessIssuer, -time.Minute)
	assert.NilError(t, err)
	for _, token := range []string{env.token(t, userID), env.token(t, adminID), expired, env.token(t, goneID)} {
		assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", map[string]string{"Authorization": token}), 200)
		assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/?token="+token, nil), 200)
	}
	// deeper, a user is judged by the table as before
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/devices", map[string]string{"Authorization": env.token(t, userID)}), 403)
}

func TestModulePageNeedsAManifest(t *testing.T) {
	env := newModuleEnv(t)
	for name, files := range map[string]map[string]string{
		"none":         {},
		"not json":     {"wake_on_lan.json": `gateway_route: /v1/wake_on_lan`},
		"not a string": {"wake_on_lan.json": `{"gateway_route":["/v1/wake_on_lan"]}`},
		"not .json":    {"wake_on_lan.conf": wakeOnLan},
		"other route":  {"other.json": `{"gateway_route":"/v1/wake"}`},
		"bad shape":    {"w.json": `{"gateway_route":"/v1/wake_on_lan/"}`},
		"too large":    {"w.json": wakeOnLan + strings.Repeat(" ", maxManifestBytes)},
	} {
		withManifests(t, files)
		assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401, name)
	}
	// no directory at all
	moduleManifestDir = filepath.Join(t.TempDir(), "missing")
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
}

// A manifest never opens a core route, nor one that is not a route key of its own.
func TestModulePageNeverACoreRoute(t *testing.T) {
	env := newModuleEnv(t)
	withManifests(t, map[string]string{
		"a.json": `{"gateway_route":"/v1/sys"}`, "b.json": `{"gateway_route":"/v2/app_management"}`,
		"c.json": `{"gateway_route":"/v1/health"}`, "d.json": `{"gateway_route":"/v2/apps"}`,
		"e.json": `{"gateway_route":"/v1/sysx"}`,            // under /v1/sys and /v1, a key of neither
		"f.json": `{"gateway_route":"/v2/app_managementx"}`, // the same
		"g.json": `{"gateway_route":"/v9/wake_on_lan"}`,     // only the dashboard's "/" route covers it
		"h.json": `{"gateway_route":"/v2/mcp"}`,
	})
	before := len(env.hits.list())
	for _, p := range []string{"/v1/sys/", "/v1/sys", "/v2/app_management/", "/v1/health/", "/v2/apps", "/v1/sysx/", "/v1/sysx", "/v2/app_managementx/"} {
		assert.Equal(t, env.call(t, "GET", p, nil), 401, p)
	}
	assert.Equal(t, len(env.hits.list()), before)
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/", nil), 200) // a module, not reserved
	// the dashboard's files answer /v9/wake_on_lan/ anyway (isStaticFile), so ask the rule itself
	g := NewGatewayRoute(env.mgmt)
	assert.Assert(t, !g.isModulePage(httptest.NewRequest("GET", "/", nil), "/v9/wake_on_lan/"))
	assert.Assert(t, g.isModulePage(httptest.NewRequest("GET", "/", nil), "/v2/mcp/"))
}

func TestModulePageSeesManifestChanges(t *testing.T) {
	env := newModuleEnv(t)
	saved := manifestRecheck
	t.Cleanup(func() { manifestRecheck = saved })
	manifestRecheck = 0
	dir := withManifests(t, nil)
	file := filepath.Join(dir, "wake_on_lan.json")
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
	assert.NilError(t, os.WriteFile(file, []byte(wakeOnLan), 0o644))
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 200)

	// overwritten in place: the directory's mtime does not move, the file's size and mtime do
	dirInfo, err := os.Stat(dir)
	assert.NilError(t, err)
	assert.NilError(t, os.WriteFile(file, []byte(`{"gateway_route":"/v2/mcp"}`), 0o644))
	assert.NilError(t, os.Chtimes(dir, dirInfo.ModTime(), dirInfo.ModTime()))
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/", nil), 200)

	assert.NilError(t, os.Remove(file))
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/", nil), 401)
}

// Within manifestRecheck the directory is not looked at again.
func TestModulePageRechecksAtMostOncePerInterval(t *testing.T) {
	env := newModuleEnv(t)
	saved := manifestRecheck
	t.Cleanup(func() { manifestRecheck = saved })
	manifestRecheck = time.Hour
	dir := withManifests(t, nil)
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "wake_on_lan.json"), []byte(wakeOnLan), 0o644))
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
}
