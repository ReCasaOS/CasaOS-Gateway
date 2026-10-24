package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/labstack/echo/v4"
	"gotest.tools/v3/assert"
)

// The management API takes the user's access token bare (as the dashboard sends it) and as
// `Bearer <token>`; another scheme, or the scheme alone, is no token.
func TestTheManagementAPITakesTheTokenBareOrAsBearer(t *testing.T) {
	defer setup(t)(t)

	// user-service stand-in: external.GetPublicKey reads its address from the runtime path
	privateKey, publicKey, err := jwt.GenerateKeyPair()
	assert.NilError(t, err)
	jwks, err := jwt.GenerateJwksJSON(publicKey)
	assert.NilError(t, err)
	userService := httptest.NewServer(jwt.JWKSHandler(jwks))
	defer userService.Close()
	assert.NilError(t, os.WriteFile(filepath.Join(_state.GetRuntimePath(), external.UserServiceAddressFilename), []byte(userService.URL), 0o600))
	token, err := jwt.GetAccessToken("admin", privateKey, 1)
	assert.NilError(t, err)

	for authorization, want := range map[string]int{
		token:              http.StatusOK,
		"Bearer " + token:  http.StatusOK,
		"bearer " + token:  http.StatusOK,
		"Basic " + token:   http.StatusUnauthorized,
		"Bearer":           http.StatusUnauthorized,
		"Bearer ":          http.StatusUnauthorized,
		"Bearer x" + token: http.StatusUnauthorized,
	} {
		req, _ := http.NewRequest(http.MethodGet, "/v1/gateway/routes", nil)
		req.RemoteAddr = "192.168.1.20:40000"
		req.Header.Set(echo.HeaderAuthorization, authorization)
		w := httptest.NewRecorder()
		_router.ServeHTTP(w, req)
		assert.Equal(t, w.Code, want, "Authorization: %.12s…", authorization)
	}
}
