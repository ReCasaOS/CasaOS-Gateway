package route

import (
	"crypto/ecdsa"
	"encoding/json"
	"net"
	"net/http"
	"path"
	"regexp"
	"strconv"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
)

// publicKey is the key the access tokens are checked with; a variable so a test can make it unreadable.
var publicKey = external.GetPublicKey

// rightsOf is the rights of a user account (fail-closed: none unless user-service answered them
// within five seconds); a variable so a test can make them unreadable.
var rightsOf = external.RightsOf

// closedForUsers wraps the path proxy: an account of role user reaches only the rows of
// allowTable, everyone else as before.
//
//   - A public row, and a file of the dashboard (what the Gateway's own "/" route serves), pass
//     at once, token or not, with no lookup: the dashboard sends its last token, expired or not,
//     with the refresh and the status it calls before signing in. So does a CORS preflight with
//     no token: the service's CORS layer answers it, before any handler.
//   - A request of the box's own services (loopback and the internal secret) passes.
//   - Anything else needs a valid access token: none, or none valid, is 401. A token the Gateway
//     cannot check (the key does not read) or whose role it cannot know (user-service has never
//     answered for it, or not lately) is 503, never a pass.
//   - A token of an account user-service says is gone is 401. An admin passes. A user passes on
//     a public or base row, and on a module row of a right it holds (rightsOf: none unless
//     user-service answered them in the last five seconds), and is refused with 403 elsewhere.
//
// The token is read from the Authorization header and from the `token` parameter (a websocket
// cannot send a header); every valid token is judged and the strictest answer wins.
//
// The services route on the raw, escaped path, so the table judges that one (see tablePath).
// Off the table an admin passes and a user is refused.
func (g *GatewayRoute) closedForUsers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		judged, tableApplies := tablePath(r)

		var tokens []string
		for _, token := range []string{jwt.TokenFromAuthorization(r.Header.Get("Authorization")), r.URL.Query().Get("token")} {
			if token != "" {
				tokens = append(tokens, token)
			}
		}
		preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" && len(tokens) == 0
		if tableApplies && allowedBy(r.Method, judged, isPublic) || preflight || g.isStaticFile(r) {
			next.ServeHTTP(w, r)
			return
		}

		runtimePath := g.management.State.GetRuntimePath()
		if external.IsInternalRequest(sourceIP(r), r.Header.Get("Authorization"), runtimePath) {
			next.ServeHTTP(w, r)
			return
		}
		if len(tokens) == 0 {
			refuse(w, http.StatusUnauthorized, common_err.ERROR_AUTH_TOKEN)
			return
		}
		key, err := publicKey(runtimePath)
		if err != nil {
			refuse(w, http.StatusServiceUnavailable, common_err.SERVICE_ERROR)
			return
		}

		valid := false
		for _, token := range tokens {
			ok, claims, err := jwt.Validate(token, func() (*ecdsa.PublicKey, error) { return key, nil })
			if err != nil || !ok {
				continue
			}
			valid = true
			// one lookup for both: an account that is gone has the role "user", and two lookups could
			// straddle the expiry of the cached answer
			role, gone, known := external.Account(runtimePath, strconv.Itoa(claims.ID))
			if gone {
				refuse(w, http.StatusUnauthorized, common_err.ERROR_AUTH_TOKEN)
				return
			}
			if !known {
				refuse(w, http.StatusServiceUnavailable, common_err.SERVICE_ERROR)
				return
			}
			// rightsOf reads the cached answer Account just used; it asks user-service again only if
			// that answer turned five seconds old in between, and a failure then is no rights
			if role != "admin" && !(tableApplies && userMayCall(r.Method, judged, rightsOf(runtimePath, strconv.Itoa(claims.ID)))) {
				refuse(w, http.StatusForbidden, common_err.INSUFFICIENT_PERMISSIONS)
				return
			}
		}
		if !valid {
			refuse(w, http.StatusUnauthorized, common_err.ERROR_AUTH_TOKEN)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isStaticFile is a GET or HEAD the Gateway's own "/" route (the dashboard's files) serves: no
// service has a route prefix for its path. That server reads files and nothing else.
func (g *GatewayRoute) isStaticFile(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	root := g.management.GetProxy("/")
	return root != nil && g.management.GetProxy(r.URL.Path) == root
}

// tablePath is the path the table judges: the escaped one, which the services route on, so an
// escape in a fixed segment (%63urrent) matches no row while one inside a parameter
// (stats/app%3Aimmich) still does. ok is false when the table does not apply: a write whose raw
// path is not its plain, clean form; a read that is not clean, a trailing slash aside, or whose
// raw path holds an encoded slash, backslash or dot, which would split segments differently.
func tablePath(r *http.Request) (p string, ok bool) {
	escaped := r.URL.EscapedPath()
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return escaped, cleanBarTrailingSlash(r.URL.Path) && !encodedSeparator.MatchString(escaped)
	}
	return escaped, r.URL.RawPath == "" && path.Clean(r.URL.Path) == r.URL.Path
}

// cleanBarTrailingSlash is true when p is its cleaned form, a trailing slash aside.
func cleanBarTrailingSlash(p string) bool {
	c := path.Clean(p)
	return p == c || p == c+"/"
}

// encodedSeparator finds %2F, %5C and %2E, also encoded again (%252F), in any case.
var encodedSeparator = regexp.MustCompile(`(?i)%(25)*(2f|5c|2e)`)

func refuse(w http.ResponseWriter, status, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(model.Result{Success: code, Message: common_err.GetMsg(code)})
}

// sourceIP is the client as rewriteRequestSourceIP left it: the forwarded address of a reverse
// proxy, else the peer. Behind a proxy on loopback this is the real client, so such a request is
// never taken for one of the box's own services.
func sourceIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return f
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
