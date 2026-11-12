package guard

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

func TestCodeHashVector(t *testing.T) {
	assert.Equal(t, NormalizeCode("abcd-efgh-jkmn"), "ABCDEFGHJKMN")
	assert.Equal(t, CodeHash(testSecret, "abcd-efgh-jkmn"), "499b46abdc484007465c1451c284ae4485de2006d52fd01cc6fa0f0c6eed12c2")
	assert.Equal(t, NormalizeCode("abcd efgh-jkmn "), "ABCDEFGHJKMN")
	assert.Equal(t, NormalizeCode("0O1IL"), "")
	assert.Equal(t, NormalizeCode("0o1il"), "")
}

func TestSessionRoundTrip(t *testing.T) {
	issued := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for _, id := range []string{"p_7f3a", "p.with.dots"} {
		tok := SignSession(testSecret, id, 2, issued)
		assert.Assert(t, strings.HasPrefix(tok, "v1."+id+".2.1794477600."), tok)
		gotID, gen, at, ok := ParseSession(testSecret, tok)
		assert.Assert(t, ok)
		assert.Equal(t, gotID, id)
		assert.Equal(t, gen, 2)
		assert.Assert(t, at.Equal(issued))
	}
}

func TestSessionRejectsTamperedSig(t *testing.T) {
	tok := SignSession(testSecret, "p1", 1, time.Unix(1794477600, 0))
	other := append([]byte(nil), testSecret...)
	other[0] ^= 1
	for _, bad := range []string{
		strings.Replace(tok, "p1", "p2", 1),
		strings.Replace(tok, ".1.", ".2.", 1),
		tok[:len(tok)-1] + "A",
		tok + "A",
		SignSession(other, "p1", 1, time.Unix(1794477600, 0)),
		"",
		"v1",
		"x.y",
	} {
		_, _, _, ok := ParseSession(testSecret, bad)
		assert.Assert(t, !ok, bad)
	}
}

func TestSessionExpiresAfter30Days(t *testing.T) {
	cfg := codeConfig(true)
	_, c, a, h := setup(t, &cfg)
	ck := sessionCookie("p1", 1, c.now())

	c.add(30*24*time.Hour - time.Minute)
	assert.Equal(t, get(h, gh, visitorIP, "/api", "Cookie", ck, "Accept", "application/json").Code, http.StatusOK)
	c.add(time.Minute)
	assert.Equal(t, get(h, gh, visitorIP, "/api", "Cookie", ck, "Accept", "application/json").Code, http.StatusUnauthorized)
	assert.Equal(t, a.hits, 1)
}
