package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

const wakeOnLan = `{"name":"wake_on_lan","gateway_route":"/v1/wake_on_lan"}`

func TestModulePageOpensWithoutToken(t *testing.T) {
	env := newReadOnlyEnv(t)
	withManifests(t, map[string]string{"wake_on_lan.json": wakeOnLan})
	for _, row := range []struct{ method, path string }{
		{"GET", "/v1/wake_on_lan/"}, {"GET", "/v1/wake_on_lan"}, {"HEAD", "/v1/wake_on_lan/"}, {"HEAD", "/v1/wake_on_lan"},
		{"GET", "/v1/wake_on_lan/?x=1"},
	} {
		before := len(env.hits.list())
		assert.Equal(t, env.call(t, row.method, row.path, nil), 200, row.method+" "+row.path)
		assert.Equal(t, len(env.hits.list()), before+1) // it reached the module
	}
	// anything deeper, another method, or a path not in its plain form is judged as before
	before := len(env.hits.list())
	for _, row := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/v1/wake_on_lan/devices", 401}, {"GET", "/v1/wake_on_lan/card", 401}, {"GET", "/v1/wake_on_lan/x/", 401},
		{"POST", "/v1/wake_on_lan/", 401}, {"PUT", "/v1/wake_on_lan", 401}, {"OPTIONS", "/v1/wake_on_lan/", 401},
		{"GET", "/v1/wake_on_lan//", 307}, // the mux cleans it first, as on any path
		{"GET", "/v1/wake_on_lan/%2e%2e/", 401}, {"GET", "/v1/wake%5Fon_lan/", 401},
		{"GET", "/v1/wake_on_lanx/", 401}, {"GET", "/v1/wake_on/", 401},
	} {
		assert.Equal(t, env.call(t, row.method, row.path, nil), row.want, row.method+" "+row.path)
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
	env := newReadOnlyEnv(t)
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
	env := newReadOnlyEnv(t)
	for name, files := range map[string]map[string]string{
		"none":         {},
		"not json":     {"wake_on_lan.json": `gateway_route: /v1/wake_on_lan`},
		"not a string": {"wake_on_lan.json": `{"gateway_route":["/v1/wake_on_lan"]}`},
		"not .json":    {"wake_on_lan.conf": wakeOnLan},
		"other route":  {"other.json": `{"gateway_route":"/v1/wake"}`},
		"bad shape":    {"w.json": `{"gateway_route":"/v1/wake_on_lan/"}`},
	} {
		withManifests(t, files)
		assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401, name)
	}
	// no directory at all
	moduleManifestDir = filepath.Join(t.TempDir(), "missing")
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
}

// A manifest never opens a core route, nor one the gateway does not proxy.
func TestModulePageNeverACoreRoute(t *testing.T) {
	env := newReadOnlyEnv(t)
	withManifests(t, map[string]string{
		"a.json": `{"gateway_route":"/v1/sys"}`, "b.json": `{"gateway_route":"/v2/app_management"}`,
		"c.json": `{"gateway_route":"/v1/health"}`, "d.json": `{"gateway_route":"/v2/apps"}`,
		"e.json": `{"gateway_route":"/v9/wake_on_lan"}`, // only the dashboard's "/" route covers it
		"f.json": `{"gateway_route":"/v2/mcp"}`,
	})
	for _, p := range []string{"/v1/sys/", "/v1/sys", "/v2/app_management/", "/v1/health/", "/v2/apps"} {
		assert.Equal(t, env.call(t, "GET", p, nil), 401, p)
	}
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/", nil), 200) // a module, not reserved
	// the dashboard's files answer /v9/wake_on_lan/ anyway (isStaticFile), so ask the rule itself
	g := NewGatewayRoute(env.mgmt)
	assert.Assert(t, !g.isModulePage("GET", "/v9/wake_on_lan/"))
	assert.Assert(t, g.isModulePage("GET", "/v2/mcp/"))
}

func TestModulePageSeesANewManifest(t *testing.T) {
	env := newReadOnlyEnv(t)
	saved := manifestRecheck
	t.Cleanup(func() { manifestRecheck = saved })
	manifestRecheck = 0
	dir := withManifests(t, nil)
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "wake_on_lan.json"), []byte(wakeOnLan), 0o644))
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 200)
	assert.NilError(t, os.Remove(filepath.Join(dir, "wake_on_lan.json")))
	assert.Equal(t, env.call(t, "GET", "/v1/wake_on_lan/", nil), 401)
}
