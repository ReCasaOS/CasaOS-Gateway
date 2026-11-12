package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/labstack/echo/v4"

	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/guard"
	"github.com/ReCasaOS/CasaOS-Gateway/service"
	"gotest.tools/v3/assert"
)

var (
	_router http.Handler
	_state  *service.State
	_secret string
	_guard  *guard.Guard
)

// asService makes a request what a service of this box sends: from loopback,
// with the secret the gateway wrote for this boot.
func asService(req *http.Request) {
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set(echo.HeaderAuthorization, _secret)
}

func init() {
	logger.LogInitConsoleOnly()
}

func setup(t *testing.T) func(t *testing.T) {
	tmpdir, _ := os.MkdirTemp("", "casaos-gateway-route-test")

	_state = service.NewState()
	if err := _state.SetRuntimePath(tmpdir); err != nil {
		t.Fatal(err)
	}
	if err := external.WriteInternalSecret(tmpdir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(tmpdir, external.InternalSecretFilename))
	if err != nil {
		t.Fatal(err)
	}
	_secret = "Internal " + strings.TrimSpace(string(raw))

	management := service.NewManagementService(_state)
	if management.Guard, err = guard.New(tmpdir, tmpdir, time.Now); err != nil {
		t.Fatal(err)
	}
	_guard = management.Guard
	managementRoute := NewManagementRoute(management)
	_router = managementRoute.GetRoute()

	return func(t *testing.T) {
		management = nil
		_router = nil
		os.RemoveAll(tmpdir)
	}
}

func TestPing(t *testing.T) {
	defer setup(t)(t)

	w := httptest.NewRecorder()

	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	asService(req)

	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateRoute(t *testing.T) {
	defer setup(t)(t)

	route := &model.Route{
		Path:   "test",
		Target: "http://localhost:8080",
	}

	body, err := json.Marshal(route)
	assert.NilError(t, err)

	req, _ := http.NewRequest(http.MethodPost, "/v1/gateway/routes", bytes.NewReader(body))
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	req, _ = http.NewRequest(http.MethodGet, "/v1/gateway/routes", nil)
	asService(req)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var routes []*model.Route

	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&routes)
	assert.NilError(t, err)
	assert.Equal(t, 1, len(routes))
	assert.Equal(t, route.Path, routes[0].Path)
	assert.Equal(t, route.Target, routes[0].Target)
}

func TestChangePort(t *testing.T) {
	defer setup(t)(t)

	actualPort := ""

	_state.OnGatewayPortChange(func(s string) error {
		actualPort = s
		return nil
	})

	expectedPort := "123"

	// set
	request := &model.ChangePortRequest{
		Port: expectedPort,
	}

	body, err := json.Marshal(request)
	assert.NilError(t, err)

	req, _ := http.NewRequest(http.MethodPut, "/v1/gateway/port", bytes.NewReader(body))
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedPort, actualPort)

	// get
	req, _ = http.NewRequest(http.MethodGet, "/v1/gateway/port", nil)
	asService(req)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result *model.Result
	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)
}

func TestChangeHTTPSPort(t *testing.T) {
	defer setup(t)(t)

	var applied string

	_state.OnHTTPSPortChange(func(port string) error {
		applied = port
		return nil
	})

	put := func(port string) *httptest.ResponseRecorder {
		body, err := json.Marshal(&model.ChangePortRequest{Port: port})
		assert.NilError(t, err)

		req, _ := http.NewRequest(http.MethodPut, "/v1/gateway/httpsport", bytes.NewReader(body))
		asService(req)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		w := httptest.NewRecorder()
		_router.ServeHTTP(w, req)

		return w
	}

	assert.Equal(t, http.StatusOK, put("0").Code)
	assert.Equal(t, "0", applied)

	req, _ := http.NewRequest(http.MethodGet, "/v1/gateway/httpsport", nil)
	asService(req)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	var result *model.Result
	assert.NilError(t, json.NewDecoder(w.Body).Decode(&result))
	assert.Equal(t, "0", result.Data)

	// a handler that refuses leaves the setting as it was
	_state.OnHTTPSPortChange(func(string) error { return errors.New("port is held") })
	assert.Equal(t, http.StatusBadRequest, put("8443").Code)
	assert.Equal(t, "0", _state.GetHTTPSPort())
}

func TestChangePortNegative(t *testing.T) {
	defer setup(t)(t)

	expectedPort := "123"

	// set
	request := &model.ChangePortRequest{
		Port: expectedPort,
	}

	body, err := json.Marshal(request)
	assert.NilError(t, err)

	req, _ := http.NewRequest(http.MethodPut, "/v1/gateway/port", bytes.NewReader(body))
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedPort, "123")

	// get
	req, _ = http.NewRequest(http.MethodGet, "/v1/gateway/port", nil)
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result *model.Result
	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)

	// emulate error
	_state.OnGatewayPortChange(func(_ string) error {
		return errors.New("error")
	})

	// set
	request.Port = "456"

	body, err = json.Marshal(request)
	assert.NilError(t, err)

	req, _ = http.NewRequest(http.MethodPut, "/v1/gateway/port", bytes.NewReader(body))
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, expectedPort, "123")

	// get
	req, _ = http.NewRequest(http.MethodGet, "/v1/gateway/port", nil)
	asService(req)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	decoder = json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)
}

// Loopback alone is any local process: a container on the host network, any
// local account. Without the secret, the management API is a person's, with a
// token.
func TestLoopbackAloneIsNotAService(t *testing.T) {
	defer setup(t)(t)

	body, err := json.Marshal(&model.ChangePortRequest{Port: "123"})
	assert.NilError(t, err)

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"changing the port", http.MethodPut, "/v1/gateway/port"},
		{"changing the HTTPS port", http.MethodPut, "/v1/gateway/httpsport"},
		{"registering a route", http.MethodPost, "/v1/gateway/routes"},
		{"listing the routes", http.MethodGet, "/v1/gateway/routes"},
	} {
		req, _ := http.NewRequest(tc.method, tc.path, bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:0"
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		w := httptest.NewRecorder()
		_router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code, tc.name)
	}
}

func hostCall(method, path, body string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, strings.NewReader(body))
	asService(req)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	return w
}

func TestPutGetDeleteHost(t *testing.T) {
	defer setup(t)(t)

	w := hostCall(http.MethodPut, "/v1/gateway/hosts", `{"host":"Jellyfin.MyBox.box.example.org","target":"http://127.0.0.1:8096"}`)
	assert.Equal(t, http.StatusCreated, w.Code)

	w = hostCall(http.MethodGet, "/v1/gateway/hosts", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `[{"host":"jellyfin.mybox.box.example.org","target":"http://127.0.0.1:8096"}]`, strings.TrimSpace(w.Body.String()))

	w = hostCall(http.MethodPut, "/v1/gateway/hosts", `{"host":"Jellyfin.MyBox.box.example.org","target":"http://127.0.0.1:8097"}`)
	assert.Equal(t, http.StatusCreated, w.Code)

	w = hostCall(http.MethodGet, "/v1/gateway/hosts", "")
	assert.Equal(t, `[{"host":"jellyfin.mybox.box.example.org","target":"http://127.0.0.1:8097"}]`, strings.TrimSpace(w.Body.String()))

	w = hostCall(http.MethodDelete, "/v1/gateway/hosts/jellyfin.mybox.box.example.org", "")
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = hostCall(http.MethodGet, "/v1/gateway/hosts", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]", strings.TrimSpace(w.Body.String()))

	w = hostCall(http.MethodDelete, "/v1/gateway/hosts/jellyfin.mybox.box.example.org", "")
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestPutHostRejectsBadInput(t *testing.T) {
	defer setup(t)(t)

	for _, tc := range []struct{ body, mentions string }{
		{`{"host":"mybox","target":"http://127.0.0.1:1"}`, "host"},
		{`{"host":"a.b.c","target":"127.0.0.1:1"}`, "target"},
		{`nope`, ""},
	} {
		w := hostCall(http.MethodPut, "/v1/gateway/hosts", tc.body)
		assert.Equal(t, http.StatusBadRequest, w.Code, tc.body)
		assert.Assert(t, strings.Contains(w.Body.String(), tc.mentions), w.Body.String())
	}
}

func TestHostsNeedTheSecretToo(t *testing.T) {
	defer setup(t)(t)

	req, _ := http.NewRequest(http.MethodPut, "/v1/gateway/hosts", strings.NewReader(`{"host":"a.b.c","target":"http://127.0.0.1:1"}`))
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGuardRoutesAreAbsentWithoutAGuard(t *testing.T) {
	defer setup(t)(t)

	_router = NewManagementRoute(service.NewManagementService(_state)).GetRoute() // no Guard set

	assert.Equal(t, http.StatusNotFound, hostCall(http.MethodGet, "/v1/gateway/guard", "").Code)
	assert.Equal(t, http.StatusNotFound, hostCall(http.MethodPut, "/v1/gateway/guard", "{}").Code)
	assert.Equal(t, http.StatusNotFound, hostCall(http.MethodGet, "/v1/gateway/guard/events", "").Code)
	assert.Equal(t, http.StatusNotFound, hostCall(http.MethodGet, "/v1/gateway/guard/bans", "").Code)
	assert.Equal(t, http.StatusNotFound, hostCall(http.MethodDelete, "/v1/gateway/guard/bans/x", "").Code)
}

func TestGuardRoutes(t *testing.T) {
	defer setup(t)(t)

	w := hostCall(http.MethodGet, "/v1/gateway/guard", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"version":1,"configured":false,"geo":{"country":false,"asn":false},"people_last_used":{},"waves":[]}`, strings.TrimSpace(w.Body.String()))

	body := `{"secret":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","protection":true,"apps":{"a.b.c":{"app":"a","access":"code","policy":{"waf":"off","rules_off":[],"allow":[],"block":[],"countries":{"mode":"none","list":[]},"rate_per_min":600,"ban":{"waf_hits":10,"waf_window_s":600,"scan_404":100,"scan_window_s":60,"rate_strikes":3,"rate_window_s":600,"code_fails":5,"code_window_s":600}}}},"people":[]}`
	w = hostCall(http.MethodPut, "/v1/gateway/guard", body)
	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

	w = hostCall(http.MethodGet, "/v1/gateway/guard", "")
	assert.Assert(t, strings.Contains(w.Body.String(), `"configured":true`), w.Body.String())

	w = hostCall(http.MethodPut, "/v1/gateway/guard", strings.Replace(body, `"waf":"off"`, `"waf":"x"`, 1))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Assert(t, strings.Contains(w.Body.String(), "policy.waf"), w.Body.String())

	w = hostCall(http.MethodPut, "/v1/gateway/guard", "not json")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// the previous config is still the one held
	w = hostCall(http.MethodGet, "/v1/gateway/guard", "")
	assert.Assert(t, strings.Contains(w.Body.String(), `"configured":true`), w.Body.String())
	assert.Equal(t, 1, len(_guard.Config().Apps))
	assert.Equal(t, "off", _guard.Config().Apps["a.b.c"].Policy.WAF)

	req, _ := http.NewRequest(http.MethodPut, "/v1/gateway/guard", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:0"
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGuardEventsAndBansRoutes(t *testing.T) {
	defer setup(t)(t)

	_guard.Record(guard.Event{Key: "203.0.113.9", IP: "203.0.113.9", App: "jellyfin", Reason: "scan", Action: "banned"})
	_guard.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")
	_guard.BanKey("2001:db8::/64", "2001:db8::1", "jellyfin", "waf")

	w := hostCall(http.MethodGet, "/v1/gateway/guard/events?app=jellyfin&reason=scan", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Assert(t, strings.Contains(w.Body.String(), `"reason":"scan"`), w.Body.String())
	w = hostCall(http.MethodGet, "/v1/gateway/guard/events?reason=nothing", "")
	assert.Equal(t, strings.TrimSpace(w.Body.String()), "[]")

	w = hostCall(http.MethodGet, "/v1/gateway/guard/bans", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 2, strings.Count(w.Body.String(), `"strikes":1`), w.Body.String())

	assert.Equal(t, http.StatusNoContent, hostCall(http.MethodDelete, "/v1/gateway/guard/bans/2001:db8::%2F64", "").Code)
	_, ok := _guard.Banned("2001:db8::/64")
	assert.Assert(t, !ok)
	_, ok = _guard.Banned("203.0.113.9")
	assert.Assert(t, ok)
	assert.Equal(t, http.StatusNoContent, hostCall(http.MethodDelete, "/v1/gateway/guard/bans/nope", "").Code)
}
