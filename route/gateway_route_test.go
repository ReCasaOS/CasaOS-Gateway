package route

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/guard"
	"github.com/ReCasaOS/CasaOS-Gateway/service"
	"gotest.tools/v3/assert"
)

const appHost = "jellyfin.mybox.box.example.org"

type seen struct {
	mu    sync.Mutex
	paths []string
}

func (s *seen) add(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, p)
}

func (s *seen) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

type shareEnv struct {
	pub, share *httptest.Server
	dash, app  *seen
}

func newShareEnv(t *testing.T, appHandler func(http.ResponseWriter, *http.Request)) *shareEnv {
	t.Helper()
	env := &shareEnv{dash: &seen{}, app: &seen{}}

	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.dash.add(r.URL.Path)
	}))
	t.Cleanup(dash.Close)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.app.add(r.URL.Path)
		if appHandler != nil {
			appHandler(w, r)
		}
	}))
	t.Cleanup(app.Close)

	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(t.TempDir()))
	management := service.NewManagementService(state)
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/v1", Target: dash.URL}))
	assert.NilError(t, management.SetHost(service.HostRoute{Host: appHost, Target: app.URL}))

	gw := NewGatewayRoute(management)
	env.pub = httptest.NewServer(gw.GetRoute())
	t.Cleanup(env.pub.Close)
	env.share = httptest.NewServer(gw.GetShareRoute())
	t.Cleanup(env.share.Close)
	return env
}

func get(t *testing.T, base, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	assert.NilError(t, err)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	assert.NilError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestSharedHostGoesToTheApp(t *testing.T) {
	for _, name := range []string{"pub", "share"} {
		t.Run(name, func(t *testing.T) {
			env := newShareEnv(t, nil)
			base := env.pub.URL
			if name == "share" {
				base = env.share.URL
			}
			code, _ := get(t, base, appHost, "/anything")
			assert.Equal(t, code, http.StatusOK)
			assert.DeepEqual(t, env.app.list(), []string{"/anything"})
			assert.Equal(t, len(env.dash.list()), 0)
		})
	}
}

func TestSharedHostNeverReachesPathRoutes(t *testing.T) {
	env := newShareEnv(t, nil)

	code, _ := get(t, env.pub.URL, appHost, "/v1/sys/x")
	assert.Equal(t, code, http.StatusOK)
	assert.DeepEqual(t, env.app.list(), []string{"/v1/sys/x"})
	assert.Equal(t, len(env.dash.list()), 0)

	code, _ = get(t, env.share.URL, "other.mybox.box.example.org", "/v1/sys/x")
	assert.Equal(t, code, http.StatusNotFound)
	assert.Equal(t, len(env.dash.list()), 0)
	assert.Equal(t, len(env.app.list()), 1) // only the first request
}

func TestSharedHostDropsClientAddressHeaders(t *testing.T) {
	var xff, realIP string
	env := newShareEnv(t, func(w http.ResponseWriter, r *http.Request) {
		xff, realIP = r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP")
	})

	req, err := http.NewRequest(http.MethodGet, env.pub.URL+"/x", nil)
	assert.NilError(t, err)
	req.Host = "Jellyfin.MyBox.box.example.org:443" // mixed case and a port still match
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	assert.NilError(t, err)
	resp.Body.Close()

	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.DeepEqual(t, env.app.list(), []string{"/x"})
	assert.Equal(t, xff, "127.0.0.1") // the test client's own address, not the claimed one
	assert.Equal(t, realIP, "")
}

func TestLANHostKeepsPathRouting(t *testing.T) {
	env := newShareEnv(t, nil)

	code, _ := get(t, env.pub.URL, "casaos.local", "/v1/x")
	assert.Equal(t, code, http.StatusOK)
	assert.DeepEqual(t, env.dash.list(), []string{"/v1/x"})

	code, body := get(t, env.pub.URL, "casaos.local", "/ping")
	assert.Equal(t, code, http.StatusOK)
	assert.Equal(t, body, "pong from gateway service")

	code, _ = get(t, env.pub.URL, "casaos.local", "/nope")
	assert.Equal(t, code, http.StatusNotFound)
	assert.Equal(t, len(env.app.list()), 0)
}

func TestShareListenerHasNoPing(t *testing.T) {
	env := newShareEnv(t, nil)
	code, _ := get(t, env.share.URL, "casaos.local", "/ping")
	assert.Equal(t, code, http.StatusNotFound)
}

func TestWebSocketPassesThroughHostRoute(t *testing.T) {
	env := newShareEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	})

	conn, err := net.Dial("tcp", env.pub.Listener.Addr().String())
	assert.NilError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: "+appHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	assert.NilError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	assert.NilError(t, err)
	assert.Equal(t, resp.StatusCode, http.StatusSwitchingProtocols)

	_, err = io.WriteString(conn, "hi\n")
	assert.NilError(t, err)
	line, err := br.ReadString('\n')
	assert.NilError(t, err)
	assert.Equal(t, line, "hi\n")
	assert.DeepEqual(t, env.app.list(), []string{"/ws"})
}

// A host behind an access code is not host-routed on the dashboard listener: it falls through to
// path routing as if it were not in the host table. Open hosts are unchanged.
func TestDashboardListenerSkipsCodeHosts(t *testing.T) {
	const openHost = "photos.mybox.box.example.org"
	env := &shareEnv{dash: &seen{}, app: &seen{}}
	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(t.TempDir()))
	management := service.NewManagementService(state)
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { env.dash.add(r.URL.Path) }))
	t.Cleanup(dash.Close)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { env.app.add(r.Host + r.URL.Path) }))
	t.Cleanup(app.Close)
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/v1", Target: dash.URL}))
	assert.NilError(t, management.SetHost(service.HostRoute{Host: appHost, Target: app.URL}))
	assert.NilError(t, management.SetHost(service.HostRoute{Host: openHost, Target: app.URL}))
	pub := httptest.NewServer(NewGatewayRoute(management).GetRoute())
	t.Cleanup(pub.Close)

	// no guard: unchanged
	code, _ := get(t, pub.URL, appHost, "/x")
	assert.Equal(t, code, http.StatusOK)
	assert.DeepEqual(t, env.app.list(), []string{appHost + "/x"})

	var err error
	management.Guard, err = guard.New(t.TempDir(), t.TempDir(), time.Now)
	assert.NilError(t, err)
	pol := guard.Policy{WAF: "off", Countries: guard.Countries{Mode: "none"}, RatePerMin: 600, Ban: guard.BanRules{
		WAFHits: 10, WAFWindowS: 600, Scan404: 100, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600}}
	assert.NilError(t, management.Guard.SetConfig(guard.Config{Secret: make([]byte, 32), Apps: map[string]guard.AppConfig{
		appHost:  {App: "jellyfin", Access: "code", Policy: pol},
		openHost: {App: "photos", Access: "open", Policy: pol},
	}}))

	for _, host := range []string{appHost, "JellyFin.mybox.box.example.org:80"} {
		code, _ = get(t, pub.URL, host, "/x")
		assert.Equal(t, code, http.StatusNotFound) // path routing: no route for /x
		code, _ = get(t, pub.URL, host, "/v1/y")
		assert.Equal(t, code, http.StatusOK) // path routing: the dashboard's route
	}
	code, _ = get(t, pub.URL, openHost, "/z")
	assert.Equal(t, code, http.StatusOK)
	assert.DeepEqual(t, env.app.list(), []string{appHost + "/x", openHost + "/z"})
	assert.DeepEqual(t, env.dash.list(), []string{"/v1/y", "/v1/y"})
}

// Only the app's own 404s count toward a scan ban, not the Gateway's for a host it does not serve.
func TestShareScanCountsOnlyTheAppsAnswers(t *testing.T) {
	const ghost = "ghost.mybox.box.example.org" // in the guard config, not in the host table
	app := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(app.Close)
	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(t.TempDir()))
	management := service.NewManagementService(state)
	assert.NilError(t, management.SetHost(service.HostRoute{Host: appHost, Target: app.URL}))
	var err error
	management.Guard, err = guard.New(t.TempDir(), t.TempDir(), time.Now)
	assert.NilError(t, err)
	pol := guard.Policy{WAF: "off", Countries: guard.Countries{Mode: "none"}, RatePerMin: 600, Ban: guard.BanRules{
		WAFHits: 10, WAFWindowS: 600, Scan404: 3, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600}}
	assert.NilError(t, management.Guard.SetConfig(guard.Config{Protection: true, Apps: map[string]guard.AppConfig{
		ghost:   {App: "ghost", Access: "open", Policy: pol},
		appHost: {App: "jellyfin", Access: "open", Policy: pol},
	}}))
	share := httptest.NewServer(NewGatewayRoute(management).GetShareRoute())
	t.Cleanup(share.Close)

	for i := 0; i < 5; i++ {
		code, _ := get(t, share.URL, ghost, "/x")
		assert.Equal(t, code, http.StatusNotFound)
	}
	_, banned := management.Guard.Banned("127.0.0.1")
	assert.Assert(t, !banned)

	for i := 0; i < 3; i++ {
		get(t, share.URL, appHost, "/x")
	}
	_, banned = management.Guard.Banned("127.0.0.1")
	assert.Assert(t, banned)
}
