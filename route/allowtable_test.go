package route

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"gotest.tools/v3/assert"
)

// shape is a route pattern with its parameters (`:x`, `{x}`, `*`) written `*`.
func shape(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "*"
		}
	}
	return strings.Join(segs, "/")
}

// Every row of the table is a route a service registers, with its method.
func TestTableRulesMatchRealRoutes(t *testing.T) {
	f, err := os.Open("testdata/routes.txt")
	if os.IsNotExist(err) {
		t.Skip("testdata/routes.txt is not there: run testdata/gen-routes.py")
	}
	assert.NilError(t, err)
	defer f.Close()

	real := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		method, p, ok := strings.Cut(line, " ")
		assert.Assert(t, ok, line)
		real[method+" "+shape(p)] = true
	}
	assert.NilError(t, scanner.Err())
	assert.Assert(t, len(real) > 0)

	for _, r := range allowTable {
		assert.Assert(t, isRealRoute(real, r.Method, r.Pattern), "no route %s %s", r.Method, r.Pattern)
	}
}

// isRealRoute: the route itself, or a leaf route whose last segment is a parameter, which echo
// gives the rest of the path, slashes and all (/v1/recover/:type takes type/state). A route with
// a longer one under it (stats/:id and stats/:id/alerts) is no leaf.
func isRealRoute(real map[string]bool, method, pattern string) bool {
	if real[method+" "+pattern] {
		return true
	}
	for p := pattern; p != ""; p = p[:strings.LastIndex(p, "/")] {
		if p != pattern && real[method+" "+p] && strings.HasSuffix(p, "/*") {
			for route := range real {
				if strings.HasPrefix(route, method+" "+p+"/") {
					return false
				}
			}
			return true
		}
	}
	return false
}

// A row is real only as a route, or under a leaf route that ends in a parameter.
func TestIsRealRouteTakesOnlyLeafParameters(t *testing.T) {
	real := map[string]bool{"GET /a/*": true, "GET /a/*/alerts": true, "GET /r/*": true}
	assert.Assert(t, isRealRoute(real, "GET", "/a/*/alerts"))
	assert.Assert(t, isRealRoute(real, "GET", "/r/*/*"))
	assert.Assert(t, !isRealRoute(real, "GET", "/a/*/x/y"))
	assert.Assert(t, !isRealRoute(real, "POST", "/r/*/*"))
}

// A module row opens its calls to a user with that right only; the others keep what they had.
func TestAModuleRowOpensWithItsRightOnly(t *testing.T) {
	saved := allowTable
	t.Cleanup(func() { allowTable = saved })
	allowTable = append(append([]rule{}, saved...), rule{"GET", "/v2/virt_management/vms", module("vm")})

	assert.Assert(t, !userMayCall("GET", "/v2/virt_management/vms", nil))
	assert.Assert(t, !userMayCall("GET", "/v2/virt_management/vms", map[string]bool{"storage": true}))
	assert.Assert(t, userMayCall("GET", "/v2/virt_management/vms", map[string]bool{"vm": true}))
	assert.Assert(t, !userMayCall("POST", "/v2/virt_management/vms", map[string]bool{"vm": true}))
	assert.Assert(t, userMayCall("GET", "/v1/users/current", nil))
	assert.Assert(t, userMayCall("POST", "/v1/users/login", nil))
	assert.Assert(t, !userMayCall("get", "/v1/users/current", nil)) // a method as given, never folded
}

// A module row is a read, opened by a right the box knows, and is a call the dashboard makes: listed in
// ui-calls.txt with that module (the other direction of TestEveryUICallIsInTheTable).
func TestModuleRowsAreKnownReadsTheDashboardMakes(t *testing.T) {
	raw, err := os.ReadFile("testdata/ui-calls.txt")
	assert.NilError(t, err)
	var listed []rule
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && !strings.HasPrefix(fields[0], "#") {
			listed = append(listed, rule{fields[0], fields[1], kind(fields[2])})
		}
	}

	rows := 0
	for _, r := range allowTable {
		name, isModule := strings.CutPrefix(string(r.Kind), "module:")
		if !isModule {
			continue
		}
		rows++
		assert.Equal(t, r.Method, "GET", r.Pattern)
		assert.Assert(t, slices.Contains(external.ValidRights(), name), "%s %s: no right %q", r.Method, r.Pattern, name)
		assert.Assert(t, slices.ContainsFunc(listed, func(c rule) bool { return c.Method == r.Method && c.Kind == r.Kind && matches(r.Pattern, c.Pattern) }),
			"%s %s (%s) is no call of ui-calls.txt", r.Method, r.Pattern, r.Kind)
	}
	assert.Assert(t, rows > 0)
}

// The MCP endpoint checks its own token, so no session token is asked; the rest of the module stays closed.
func TestMCPServerIsPublic(t *testing.T) {
	env := newReadOnlyEnv(t)
	before := len(env.hits.list())
	assert.Equal(t, env.call(t, "POST", "/v2/mcp/server", nil), 200)
	assert.Equal(t, env.call(t, "POST", "/v2/mcp/server", map[string]string{"Authorization": env.token(t, userID)}), 200)
	assert.Equal(t, len(env.hits.list()), before+2) // both reached the module
}

func TestMCPTokensStayClosed(t *testing.T) {
	env := newReadOnlyEnv(t)
	before := len(env.hits.list())
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/tokens", nil), 401)
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/tokens", map[string]string{"Authorization": env.token(t, userID)}), 403)
	assert.Equal(t, env.call(t, "GET", "/v2/mcp/status", map[string]string{"Authorization": env.token(t, userID)}), 403)
	assert.Equal(t, len(env.hits.list()), before) // none reached the module
}
