package route

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Gateway/service"
	"gotest.tools/v3/assert"
)

// ids the stand-in user service knows; the role cache of Common is global, so each id keeps one role
const (
	adminID       = 1
	userID        = 2
	unknownID     = 3 // a bare 404, as an older user service without the role route gives: no answer
	goneID        = 4 // the user service answers that it has no such account
	slowID        = 5 // the user service does not answer in time
	lastingAdmin  = 6 // an admin asked for in one test only
	neverAnswered = 7 // an id asked for only while the user service is down
	allRights     = 8 // a user with every right
	fadingRights  = 9 // a user with the vm right, asked for in one test only
)

// rightIDs is a user holding that one right, for each right.
var rightIDs = map[string]int{"storage": 10, "vm": 11, "backups": 12, "fleet": 13, "system": 14}

// folderID is a user given one folder of Files, and no right.
const folderID = 15

var (
	keyOnce  sync.Once
	signKey  *ecdsa.PrivateKey
	jwksJSON []byte
)

// testKeys is the one signing key of the tests of this package.
func testKeys(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	keyOnce.Do(func() {
		var pub *ecdsa.PublicKey
		var err error
		signKey, pub, err = jwt.GenerateKeyPair()
		assert.NilError(t, err)
		jwksJSON, err = jwt.GenerateJwksJSON(pub)
		assert.NilError(t, err)
	})
	return signKey, jwksJSON
}

type readOnlyEnv struct {
	gateway     *httptest.Server
	userService *httptest.Server
	hits        *seen
	files       *seen // what the Gateway's "/" route (the dashboard's files) got
	roles       *seen // the role requests the user service got
	dir         string
	mgmt        *service.Management
}

func newReadOnlyEnv(t *testing.T) *readOnlyEnv {
	t.Helper()
	_, jwksDoc := testKeys(t)

	userService := http.NewServeMux()
	userService.Handle("/.well-known/jwks.json", jwt.JWKSHandler(jwksDoc))
	env := &readOnlyEnv{hits: &seen{}, files: &seen{}, roles: &seen{}, dir: t.TempDir()}
	userService.HandleFunc("/v1/users/role/", func(w http.ResponseWriter, r *http.Request) {
		env.roles.add(r.URL.Path)
		switch strings.TrimPrefix(r.URL.Path, "/v1/users/role/") {
		case "1", "6":
			_, _ = w.Write([]byte(`{"success":200,"data":"admin"}`))
		case "2":
			_, _ = w.Write([]byte(`{"success":200,"data":"user"}`))
		case "8":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["storage","vm","backups","fleet","system"]}`))
		case "9", "11":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["vm"]}`))
		case "10":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["storage"]}`))
		case "12":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["backups"]}`))
		case "13":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["fleet"]}`))
		case "14":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":["system"]}`))
		case "15":
			_, _ = w.Write([]byte(`{"success":200,"data":"user","rights":[],"folders":[{"path":"/DATA/Kids","write":true}]}`))
		case "4":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":10006,"message":"User does not exist"}`))
		case "5":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	env.userService = httptest.NewServer(userService)
	t.Cleanup(env.userService.Close)

	assert.NilError(t, os.WriteFile(filepath.Join(env.dir, external.UserServiceAddressFilename), []byte(env.userService.URL), 0o600))
	assert.NilError(t, external.WriteInternalSecret(env.dir))

	// the path the service routes on (escaped) and the decoded one, so a mismatch between them shows
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.hits.add(r.Method + " " + r.URL.EscapedPath() + " " + r.URL.Path)
	}))
	t.Cleanup(backend.Close)
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { env.files.add(r.Method + " " + r.URL.Path) }))
	t.Cleanup(files.Close)

	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(env.dir))
	management := service.NewManagementService(state)
	for _, p := range []string{"/v1", "/v2", "/v3"} {
		assert.NilError(t, management.CreateRoute(&model.Route{Path: p, Target: backend.URL}))
	}
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/", Target: files.URL}))
	env.mgmt = management
	env.gateway = httptest.NewServer(NewGatewayRoute(management).GetRoute())
	t.Cleanup(env.gateway.Close)

	return env
}

func (e *readOnlyEnv) token(t *testing.T, id int) string {
	t.Helper()
	signKey, _ := testKeys(t)
	token, err := jwt.GetAccessToken("someone", signKey, id)
	assert.NilError(t, err)
	return token
}

func (e *readOnlyEnv) call(t *testing.T, method, path string, header map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(method, e.gateway.URL+path, nil)
	assert.NilError(t, err)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	assert.NilError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// noRedirect shows what the gateway answered, not where a redirect would lead.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *readOnlyEnv) internal(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, external.InternalSecretFilename))
	assert.NilError(t, err)
	return "Internal " + strings.TrimSpace(string(raw))
}

// What a user may call, and what the gateway refuses, one row per call.
var userTable = []struct {
	method, path string
	want         int
}{
	{"GET", "/v2/app_management/web/appgrid", 200},
	{"HEAD", "/v2/app_management/web/appgrid", 200},
	{"OPTIONS", "/v2/app_management/web/appgrid", 403},
	{"GET", "/v2/app_management/logs/stream", 200}, // a websocket that only reads
	{"GET", "/v2/app_management/apps", 403},        // the store: not on the table
	{"GET", "/v1/sys/utilization", 403},
	{"GET", "/v1/file/ws", 403},
	{"GET", "/v2/message_bus/socket.io/", 403},
	{"POST", "/v2/app_management/compose", 403},
	{"PUT", "/v2/app_management/compose/x/status", 403},
	{"DELETE", "/v2/app_management/compose/x", 403},
	{"PATCH", "/v2/app_management/compose/x", 403},
	{"POST", "/v1/sys/update", 403},
	{"PUT", "/v1/share/name", 403},
	{"DELETE", "/v1/file", 403},
	{"GET", "/v1/users", 403},
	{"POST", "/v1/users", 403},
	{"DELETE", "/v1/users/7", 403},
	{"DELETE", "/v1/users", 403},
	{"GET", "/v1/users/name", 403},
	{"GET", "/v1/users/someone", 403},
	{"PUT", "/v1/users/current/", 403}, // a write on a path not in its plain form is judged as any write
	{"PUT", "/v1/users/other", 403},
	{"POST", "/v1/users/current/custom", 403},
	{"PUT", "/v1/users/current/custom/layout", 403},   // no such route
	{"DELETE", "/v1/users/current/image/avatar", 403}, // no such route
	{"POST", "/v1/users/login", 200},
	{"POST", "/v1/users/refresh", 200},
	{"POST", "/v1/users/2fa/verify", 200},
	{"POST", "/v1/users/2fa/setup", 200},
	{"POST", "/v1/users/2fa/enable", 200},
	{"POST", "/v1/users/2fa/disable", 200},
	{"PUT", "/v1/users/current", 200},
	{"PUT", "/v1/users/current/password", 200},
	{"GET", "/v1/users/current/custom/layout", 200},
	{"POST", "/v1/users/current/custom/layout", 200},
	{"DELETE", "/v1/users/current/custom/layout", 200},
	{"POST", "/v1/users/current/image/avatar", 200},
	{"PUT", "/v1/users/current/image/avatar", 200},
	{"DELETE", "/v1/users/current/image", 200},
	{"PUT", "/v1/users/avatar", 200},
	{"PUT", "/v1/users/login-style", 403}, // the sign-in page of the whole box
	{"GET", "/v2/app_management/visibility/immich", 403},
	{"PUT", "/v2/app_management/visibility/immich", 403},
	{"DELETE", "/v2/app_management/visibility/immich", 403},
	{"GET", "/v2/app_management/visibility-orphans", 403},
	{"DELETE", "/v2/app_management/visibility/accounts/7", 403},
	// encoded paths: the service behind may route on the raw form, so the table does not apply
	{"POST", "/v1/notify/..%2Fusers%2Fcurrent%2Fcustom%2Fz", 403},
	{"PUT", "/v1/users/%63urrent", 403},
	{"POST", "/v1/users/current%2Fcustom%2Fz", 403},
	// an escape in a fixed segment is another route to the service (a parameter), never the row
	{"GET", "/v1/users/%63urrent", 403},
	{"GET", "/v1/users/%61vatar", 403},
	{"GET", "/v1/users/st%61tus", 403},
	{"GET", "/v1/users/im%61ge", 403},
	// a read passes with escapes inside a parameter, not with an encoded slash or dot
	{"GET", "/v2/app_management/stats/app%3Aimmich%3Adb%3A1", 200},
	{"GET", "/v2/app_management/logs%2Fapps", 403},
	{"GET", "/v2/app_management/logs/..%2Fapps", 403},
	// a trailing slash lands on a parameter of a sibling route, except on a row ending in one
	{"GET", "/v2/app_management/web/appgrid/", 403},
	{"GET", "/v1/users/current/", 403},
	{"GET", "/v1/users/image/", 403},
	{"GET", "/v1/users/status/", 403},
	{"GET", "/v1/users/current/custom/layout/", 200},
	{"GET", "/v1/fleet/boxes/b1/relay/v1/sys/utilization", 403},
	{"GET", "/v1/fleet/boxes", 403},
	{"GET", "/v1/fleet/tunnel", 200}, // public: a member box proves itself with its own code
}

func TestUserTable(t *testing.T) {
	env := newReadOnlyEnv(t)
	for _, row := range userTable {
		t.Run(row.method+" "+row.path, func(t *testing.T) {
			before := len(env.hits.list())
			got := env.call(t, row.method, row.path, map[string]string{"Authorization": env.token(t, userID)})
			assert.Equal(t, got, row.want)
			if row.want == 403 {
				assert.Equal(t, len(env.hits.list()), before) // never reached the service
			}
		})
	}
}

func TestTheRefusalIsTheUsualResult(t *testing.T) {
	env := newReadOnlyEnv(t)
	req, _ := http.NewRequest("POST", env.gateway.URL+"/v2/app_management/compose", nil)
	req.Header.Set("Authorization", "Bearer "+env.token(t, userID))
	resp, err := http.DefaultClient.Do(req)
	assert.NilError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, resp.StatusCode, 403)
	assert.Equal(t, resp.Header.Get("Content-Type"), "application/json")
	var res model.Result
	assert.NilError(t, json.NewDecoder(resp.Body).Decode(&res))
	assert.Equal(t, res.Success, 10011)
	assert.Assert(t, res.Message != "")
}

func TestTokenInQueryStringIsJudgedLikeTheHeader(t *testing.T) {
	env := newReadOnlyEnv(t)
	token := env.token(t, userID)
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose?token="+token, nil), 403)
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh?token="+token, nil), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/logs/stream?token="+token, nil), 200)
	assert.Equal(t, env.call(t, "GET", "/v1/users/avatar?token="+token, nil), 200)
	assert.Equal(t, env.call(t, "GET", "/v2/message_bus/socket.io/?token="+token, nil), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/logs/stream/..%2F..%2F..%2Fv1%2Fsys%2Fwsssh?token="+token, nil), 403)
	// a user's token in the query counts even when the header holds something that is no token
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose?token="+token, map[string]string{"Authorization": "garbage"}), 403)
	// the strictest of two valid tokens wins
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh?token="+token, map[string]string{"Authorization": env.token(t, adminID)}), 403)
	// a stale token next to a valid one opens nothing and closes nothing
	assert.Equal(t, env.call(t, "GET", "/v1/users/current?token=garbage", map[string]string{"Authorization": token}), 200)
	// an admin's passes
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh?token="+env.token(t, adminID), nil), 200)
}

func TestInternalRequestPasses(t *testing.T) {
	env := newReadOnlyEnv(t)
	internal := map[string]string{"Authorization": env.internal(t)}
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", internal), 200)
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh", internal), 200)
	// a wrong secret is nobody
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh", map[string]string{"Authorization": "Internal " + strings.Repeat("0", 64)}), 401)
}

// An admin passes everything, on any path form and any method, once its role is known.
func TestAdminPassesEverythingWithKnownRole(t *testing.T) {
	env := newReadOnlyEnv(t)
	h := map[string]string{"Authorization": env.token(t, adminID)}
	for _, row := range []struct{ method, path string }{
		{"POST", "/v2/app_management/compose"}, {"DELETE", "/v1/users/7"}, {"GET", "/v1/sys/wsssh"},
		{"GET", "/v1/users"}, {"PUT", "/v2/app_management/visibility/immich"}, {"GET", "/v2/app_management/visibility-orphans"},
		{"PUT", "/v1/users/%63urrent"}, {"GET", "/v1/users/%63urrent"}, {"POST", "/v1/users/current%2Fcustom%2Fz"},
		{"PUT", "/v1/users/current/"}, {"GET", "/v1/fleet/boxes/b1/relay/v1/sys/utilization"},
		{"PATCH", "/v2/app_management/compose/x"}, {"OPTIONS", "/v2/app_management/compose"},
	} {
		assert.Equal(t, env.call(t, row.method, row.path, h), 200, row.method+" "+row.path)
	}
}

// The gate judges the path the service behind may route on: a request whose raw path is not
// its plain decoded form never takes the table, whatever the mux did before.
func TestGateJudgesTheRawPath(t *testing.T) {
	env := newReadOnlyEnv(t)
	reached := false
	gate := NewGatewayRoute(env.mgmt).closedForUsers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	for _, row := range []struct{ method, path, raw string }{
		{"POST", "/v1/notify/../users/current/custom/z", "/v1/notify/..%2Fusers%2Fcurrent%2Fcustom%2Fz"},
		{"POST", "/v1/users/current/custom/z", "/v1/users/current%2Fcustom%2Fz"},
		{"GET", "/v2/app_management/logs/apps", "/v2/app_management/logs%2Fapps"},
	} {
		reached = false
		r := httptest.NewRequest(row.method, "/", nil)
		r.URL.Path, r.URL.RawPath = row.path, row.raw
		r.Header.Set("Authorization", env.token(t, userID))
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		assert.Equal(t, w.Code, 403, row.raw)
		assert.Assert(t, !reached, row.raw)
	}
}

// A token of an account that is gone is refused, reads included, with the usual result.
func TestGoneAccountIs401(t *testing.T) {
	env := newReadOnlyEnv(t)
	token := env.token(t, goneID)
	for _, row := range []struct{ method, path string }{
		{"GET", "/v2/app_management/web/appgrid"}, {"POST", "/v2/app_management/compose"}, {"PUT", "/v1/users/current"},
		{"GET", "/v1/sys/wsssh"},
	} {
		before := len(env.hits.list())
		req, _ := http.NewRequest(row.method, env.gateway.URL+row.path, nil)
		req.Header.Set("Authorization", token)
		resp, err := noRedirect.Do(req)
		assert.NilError(t, err)
		var res model.Result
		_ = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		assert.Equal(t, resp.StatusCode, 401, row.method+" "+row.path)
		assert.Equal(t, res.Success, 401)
		assert.Equal(t, len(env.hits.list()), before)
	}
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid?token="+token, nil), 401)
	// a public call stays public
	assert.Equal(t, env.call(t, "POST", "/v1/users/login", map[string]string{"Authorization": token}), 200)
	// the others are as they were
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", map[string]string{"Authorization": env.token(t, userID)}), 200)
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", map[string]string{"Authorization": env.token(t, adminID)}), 200)
}

// Without a valid access token, only the public rows and the dashboard's files pass.
func TestNoTokenOnPublicRoutesPasses(t *testing.T) {
	env := newReadOnlyEnv(t)
	signKey, _ := testKeys(t)
	expired, err := jwt.GenerateToken("someone", signKey, userID, jwt.AccessIssuer, -time.Minute)
	assert.NilError(t, err)
	refresh, err := jwt.GetRefreshToken("someone", signKey, userID)
	assert.NilError(t, err)
	for _, h := range []map[string]string{nil, {"Authorization": "not.a.token"}, {"Authorization": expired}, {"Authorization": refresh}} {
		for _, row := range []struct{ method, path string }{
			{"GET", "/v1/users/status"}, {"POST", "/v1/users/login"}, {"POST", "/v1/users/2fa/verify"},
			{"POST", "/v1/users/refresh"}, {"POST", "/v1/users/register"}, {"GET", "/v1/users/image?path=/var/lib/casaos/1/avatar.png"},
			{"GET", "/v1/fleet/tunnel"}, {"GET", "/v1/recover/GoogleDrive/state/?code=x"}, {"POST", "/v2/app_management/git/blog/webhook"},
			{"GET", "/v1/sys/version/current"},
		} {
			assert.Equal(t, env.call(t, row.method, row.path, h), 200, row.method+" "+row.path)
		}
		before := len(env.files.list())
		for _, p := range []string{"/", "/index.html", "/app.0123abcd.js", "/img/icon/a.svg", "/modules/vm/index.html"} {
			assert.Equal(t, env.call(t, "GET", p, h), 200, p)
		}
		assert.Equal(t, len(env.files.list()), before+5) // all of them reached the files, not a service
		// anything else is 401, reads included, and never reaches a service
		before = len(env.hits.list())
		for _, row := range []struct{ method, path string }{
			{"GET", "/v1/users/current"}, {"GET", "/v2/app_management/web/appgrid"}, {"POST", "/v2/app_management/compose"},
			{"GET", "/v1/sys/version/check"}, {"GET", "/v1/users/status/x"}, {"POST", "/v1/users/login/x"},
			{"POST", "/index.html"}, {"GET", "/v2/app_management/logs/stream"}, {"OPTIONS", "/v1/users/current"},
		} {
			assert.Equal(t, env.call(t, row.method, row.path, h), 401, row.method+" "+row.path)
		}
		assert.Equal(t, len(env.hits.list()), before)
	}
	// a CORS preflight carries no token: the service's CORS layer answers it
	assert.Equal(t, env.call(t, "OPTIONS", "/v1/gateway/port", map[string]string{"Origin": "http://box:8080", "Access-Control-Request-Method": "GET"}), 200)
}

// A request with no token, or with one that is no valid access token, never makes the gateway ask
// the user service; neither does a public call.
func TestNoTokenNoRoleLookup(t *testing.T) {
	env := newReadOnlyEnv(t)
	before := len(env.roles.list())
	assert.Equal(t, env.call(t, "GET", "/v1/users/status", map[string]string{"Authorization": env.token(t, goneID)}), 200)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", nil), 401)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", map[string]string{"Authorization": "not.a.token"}), 401)
	assert.Equal(t, env.call(t, "GET", "/ping", map[string]string{"Authorization": env.token(t, goneID)}), 200)
	assert.Equal(t, len(env.roles.list()), before)
}

// The table judges the path the service routes on: another spelling of a public call is not
// public, and what a user's call reaches is the path the table read.
func TestTheTableJudgesThePathTheServiceRoutesOn(t *testing.T) {
	env := newReadOnlyEnv(t)
	for _, p := range []string{"/v1/users/st%61tus", "/v1/users/im%61ge", "/v1/users/image/", "/v1/users/status/", "/v1/users/%63urrent"} {
		before := len(env.hits.list())
		assert.Equal(t, env.call(t, "GET", p, nil), 401, p)
		assert.Equal(t, len(env.hits.list()), before, p)
	}
	h := map[string]string{"Authorization": env.token(t, userID)}
	for _, p := range []string{"/v2/app_management/stats/app%3Aimmich", "/v1/users/current/custom/layout/", "/v1/recover/GoogleDrive/state/"} {
		assert.Equal(t, env.call(t, "GET", p, h), 200, p)
		hits := env.hits.list()
		escaped, _, _ := strings.Cut(strings.TrimPrefix(hits[len(hits)-1], "GET "), " ")
		assert.Equal(t, escaped, p)
	}
}

// Every route that is not a row of the table is refused to a user, whatever the service.
func TestUnknownRouteRefusedForUser(t *testing.T) {
	env := newReadOnlyEnv(t)
	h := map[string]string{"Authorization": env.token(t, userID)}
	for _, row := range []struct{ method, path string }{
		{"GET", "/v1/file/content"}, {"GET", "/v1/zt/x"}, {"GET", "/v1/other/search"}, {"GET", "/v1/sys/proxy"},
		{"GET", "/v2/virt_management/vms/1/console"}, {"POST", "/v2/message_bus/event/app-management"},
		{"GET", "/v2/app_management/global"}, {"GET", "/v1/container/1/terminal"},
		{"GET", "/v1/fleet/boxes/1/relay/x"}, {"GET", "/v2/app_management/compose/x/env"}, {"GET", "/v2/app_management/compose/x"},
		{"GET", "/v1/sys/wsssh"}, {"GET", "/v1/sys/packages"}, {"GET", "/v1/sys/os/upgrade/runbook"},
		{"GET", "/v2/app_management/backup/destinations/d1/restic/password"}, {"GET", "/v2/app_management/backup/runs"},
		{"GET", "/v1/sys/version"}, {"GET", "/v1/sys/hardware"}, {"GET", "/v2/users/events"}, {"DELETE", "/v2/users/event/x"},
		{"GET", "/v2/local_storage/mount"}, {"GET", "/v1/storage"}, {"GET", "/v2/virt_management/host"},
		{"GET", "/v1/fleet"}, {"GET", "/v1/gateway/port"}, {"GET", "/v2/app_management/web/frame-check"},
		{"GET", "/v3/file"}, {"GET", "/v1/image"}, {"POST", "/v1/notify/system_status"},
	} {
		before := len(env.hits.list())
		assert.Equal(t, env.call(t, row.method, row.path, h), 403, row.method+" "+row.path)
		assert.Equal(t, len(env.hits.list()), before, row.method+" "+row.path)
	}
}

// A path that is not one of the table in its plain form opens nothing, for a user.
func TestPathTricksNeverOpenAnything(t *testing.T) {
	env := newReadOnlyEnv(t)
	h := map[string]string{"Authorization": env.token(t, userID)}
	for _, row := range []struct{ method, path string }{
		{"GET", "/V1/USERS/CURRENT"}, {"GET", "/v2/App_Management/web/appgrid"},
		{"GET", "//v1/sys/wsssh"}, {"GET", "/v1//sys/wsssh"}, {"GET", "/v1/users//../../sys/wsssh"},
		{"PUT", "/v1/users//current"}, {"POST", "/v1/users/current/custom//x"},
		{"GET", "/v1/users/current%2F..%2F..%2Fsys%2Fwsssh"}, {"GET", "/v1%2Fsys%2Fwsssh"},
		{"GET", "/v2/app_management/logs/stream/%2e%2e/%2e%2e/%2e%2e/v1/sys/wsssh"}, {"GET", "/v2/app_management/stats/%2e%2e"},
		{"GET", "/v1/users/current;x"}, {"PUT", "/v1/users/current;x"}, {"GET", "/v2/app_management/web/appgrid;/../../../v1/sys/wsssh"},
		{"get", "/v1/users/current"}, {"put", "/v1/users/current"},
		{"PATCH", "/v1/users/current"}, {"TRACE", "/v1/users/current"}, {"PATCH", "/v1/users/current/custom/x"},
		{"PROPFIND", "/v1/users/current"},
	} {
		before, files := len(env.hits.list()), len(env.files.list())
		got := env.call(t, row.method, row.path, h)
		// refused, or sent to its clean form, or (no service has the prefix) to the dashboard's files
		assert.Assert(t, got == 403 || got/100 == 3 || got == 200 && len(env.files.list()) == files+1, "%s %s: %d", row.method, row.path, got)
		assert.Equal(t, len(env.hits.list()), before, row.method+" "+row.path)
	}
}

// A token the gateway cannot check, or whose role it cannot know, is 503 on any call that is not
// public: never a pass.
func TestUnverifiableTokenIs503(t *testing.T) {
	env := newReadOnlyEnv(t)

	// the key does not read
	saved := publicKey
	t.Cleanup(func() { publicKey = saved })
	publicKey = func(string) (*ecdsa.PublicKey, error) { return nil, errors.New("no key") }
	for _, id := range []int{adminID, userID} {
		h := map[string]string{"Authorization": env.token(t, id)}
		assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 503)
		assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", h), 503)
		assert.Equal(t, env.call(t, "POST", "/v1/users/refresh", h), 200) // public
	}
	publicKey = saved

	// no answer from the user service: an older one (a bare 404), one that is too slow, one that is down
	before := len(env.hits.list())
	h := map[string]string{"Authorization": env.token(t, unknownID)}
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 503)
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", h), 503)

	h = map[string]string{"Authorization": env.token(t, slowID)}
	start := time.Now()
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 503)
	assert.Assert(t, time.Since(start) < 4*time.Second, time.Since(start))
	start = time.Now()
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 503) // the failure is not asked again at once
	assert.Assert(t, time.Since(start) < 500*time.Millisecond, time.Since(start))

	h = map[string]string{"Authorization": env.token(t, neverAnswered)}
	env.userService.Close()
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 503)
	assert.Equal(t, env.call(t, "GET", "/v1/users/status", h), 200) // public
	assert.Equal(t, len(env.hits.list()), before+1)                 // only the public call
}

// An admin's role, once the user service has answered it, outlives the user service.
func TestAdminOutlivesUserServiceDown(t *testing.T) {
	t.Parallel()
	env := newReadOnlyEnv(t)
	h := map[string]string{"Authorization": env.token(t, lastingAdmin)}
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", h), 200)
	env.userService.Close()
	time.Sleep(5100 * time.Millisecond) // past the five seconds an answer is fresh
	assert.Equal(t, env.call(t, "POST", "/v2/app_management/compose", h), 200)
	assert.Equal(t, env.call(t, "GET", "/v1/sys/wsssh", h), 200)
}

// A right opens the reads of its module, and nothing of another module, nor what the module keeps for the owner.
func TestModuleRights(t *testing.T) {
	env := newReadOnlyEnv(t)
	as := func(id int) map[string]string { return map[string]string{"Authorization": env.token(t, id)} }
	for _, row := range []struct {
		id           int
		method, path string
		want         int
	}{
		{folderID, "GET", "/v1/folder", 200},
		{folderID, "DELETE", "/v1/batch", 200},
		{folderID, "GET", "/v1/file/trash", 403},
		{folderID, "POST", "/v1/file/trash/restore", 403},
		{folderID, "DELETE", "/v1/file/trash/all", 403},
		{folderID, "GET", "/v1/file/ws", 403},
		{folderID, "GET", "/v1/file/peers", 403},
		{folderID, "POST", "/v1/file/upload", 403},
		{folderID, "DELETE", "/v1/batch/0/task", 403},
		{folderID, "GET", "/v1/samba/shares", 403},
		{folderID, "GET", "/v1/cloud", 403},
		{folderID, "GET", "/v1/disks", 403},
		{rightIDs["storage"], "GET", "/v1/folder", 403},
		{rightIDs["storage"], "GET", "/v1/disks", 200},
		{rightIDs["storage"], "GET", "/v1/storage", 200},
		{rightIDs["storage"], "GET", "/v2/virt_management/vms", 403},
		{rightIDs["storage"], "GET", "/v1/sys/utilization", 403},
		{rightIDs["storage"], "DELETE", "/v1/disks", 403},
		{rightIDs["storage"], "GET", "/v1/disks/usb", 403},
		{rightIDs["storage"], "GET", "/v2/local_storage/mount", 403},
		{rightIDs["storage"], "GET", "/v1/disks/unreadable", 403}, // runs df on every call: the owner's
		{rightIDs["vm"], "GET", "/v2/virt_management/vms", 200},
		{rightIDs["vm"], "GET", "/v2/virt_management/vms/0f3c", 200},
		{rightIDs["vm"], "GET", "/v2/virt_management/host", 200},
		{rightIDs["vm"], "GET", "/v1/disks", 403},
		{rightIDs["vm"], "GET", "/v2/virt_management/vms/0f3c/console", 403},
		{rightIDs["vm"], "GET", "/v2/virt_management/vms/0f3c/console/", 403},
		{rightIDs["vm"], "GET", "/v2/virt_management/vms/0f3c%2Fconsole", 403},
		{rightIDs["vm"], "POST", "/v2/virt_management/vms/0f3c/start", 403},
		{rightIDs["vm"], "PATCH", "/v2/virt_management/vms/0f3c", 403},
		{rightIDs["vm"], "GET", "/v2/virt_management/images", 403},
		{rightIDs["vm"], "GET", "/v2/virt_management/storage", 403},
		{rightIDs["backups"], "GET", "/v2/app_management/backup/runs", 200},
		{rightIDs["backups"], "GET", "/v2/app_management/backup/destinations/d1/restic/password", 403},
		{rightIDs["backups"], "GET", "/v2/app_management/backup/destinations/d1/runs", 403},
		{rightIDs["backups"], "POST", "/v2/app_management/backup/schedules/run", 403},
		{rightIDs["fleet"], "GET", "/v1/fleet", 200},
		{rightIDs["fleet"], "GET", "/v1/fleet/boxes/b1/relay/v1/sys/utilization", 403},
		{rightIDs["fleet"], "GET", "/v1/fleet/backups", 403},
		{rightIDs["fleet"], "GET", "/v1/fleet/remote", 403},
		{rightIDs["system"], "GET", "/v1/sys/utilization", 200},
		{rightIDs["system"], "GET", "/v1/sys/stats/host", 200},
		{rightIDs["system"], "GET", "/v1/sys/logs", 403},
		{rightIDs["system"], "GET", "/v1/sys/wsssh", 403},
		{rightIDs["system"], "PUT", "/v1/sys/stats/host/alerts", 403},
		{rightIDs["system"], "GET", "/v1/disks", 403},
		// every right at once still keeps the owner's reads out
		{allRights, "GET", "/v2/virt_management/vms/0f3c/console", 403},
		{allRights, "GET", "/v2/app_management/backup/destinations/d1/restic/password", 403},
		{allRights, "GET", "/v1/fleet/boxes/b1/relay/v1/sys/utilization", 403},
		{allRights, "GET", "/v1/sys/logs", 403},
		{allRights, "GET", "/v1/container/1/terminal", 403},
		{allRights, "GET", "/v1/file/content", 403},
		{allRights, "GET", "/v2/app_management/images/dangling", 403},
		{allRights, "GET", "/v1/disks", 200},
		{allRights, "GET", "/v2/virt_management/vms", 200},
		// no right opens no module
		{userID, "GET", "/v1/disks", 403},
		{userID, "GET", "/v2/virt_management/vms", 403},
		{userID, "GET", "/v1/fleet", 403},
	} {
		before := len(env.hits.list())
		got := env.call(t, row.method, row.path, as(row.id))
		assert.Equal(t, got, row.want, "%d %s %s", row.id, row.method, row.path)
		if row.want == 403 {
			assert.Equal(t, len(env.hits.list()), before, "%d %s %s", row.id, row.method, row.path)
		}
	}
	// a websocket's token in the query is judged the same way
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms/0f3c/console?token="+env.token(t, allRights), nil), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms?token="+env.token(t, rightIDs["vm"]), nil), 200)
	// the owner passes as before
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms/0f3c/console", as(adminID)), 200)
}

// Rights that cannot be read are no rights: the module rows close, the base stays open.
func TestUnreadableRightsAreNoRights(t *testing.T) {
	env := newReadOnlyEnv(t)
	saved := rightsOf
	t.Cleanup(func() { rightsOf = saved })
	rightsOf = func(string, string) map[string]bool { return map[string]bool{} }
	h := map[string]string{"Authorization": env.token(t, allRights)}
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms", h), 403)
	assert.Equal(t, env.call(t, "GET", "/v1/disks", h), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 200)
}

// With the user service down, a user keeps its role for a while but loses its rights at once: a
// right is read only from a fresh answer.
func TestRightsFailClosedWhenTheUserServiceIsDown(t *testing.T) {
	t.Parallel()
	env := newReadOnlyEnv(t)
	h := map[string]string{"Authorization": env.token(t, fadingRights)}
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms", h), 200)
	env.userService.Close()
	time.Sleep(5100 * time.Millisecond) // past the five seconds an answer is fresh
	assert.Equal(t, env.call(t, "GET", "/v2/virt_management/vms", h), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/app_management/web/appgrid", h), 200)
}
