package guard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NormalizeCode uppercases s (ASCII only) and drops every character outside the code alphabet.
func NormalizeCode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		if strings.IndexByte(codeAlphabet, c) >= 0 {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func mac(secret []byte, s string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// CodeHash is the lowercase hex HMAC-SHA256 of the normalised code: the person's code_hash.
func CodeHash(secret []byte, code string) string {
	return hex.EncodeToString(mac(secret, NormalizeCode(code)))
}

// SignSession returns v1.<person id>.<gen>.<issued unix seconds>.<sig>.
func SignSession(secret []byte, personID string, gen int, issued time.Time) string {
	body := "v1." + personID + "." + strconv.Itoa(gen) + "." + strconv.FormatInt(issued.Unix(), 10)
	return body + "." + base64.RawURLEncoding.EncodeToString(mac(secret, body))
}

// cutLast splits s around its last dot.
func cutLast(s string) (before, after string, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ParseSession checks the signature and splits the token; the age is the caller's to judge. Parsed
// from the right, so a person id holding a dot survives.
func ParseSession(secret []byte, token string) (personID string, gen int, issued time.Time, ok bool) {
	body, sig, ok := cutLast(token)
	if !ok {
		return "", 0, time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(raw, mac(secret, body)) {
		return "", 0, time.Time{}, false
	}
	rest, ok := strings.CutPrefix(body, "v1.")
	if !ok {
		return "", 0, time.Time{}, false
	}
	rest, issuedS, _ := cutLast(rest)
	id, genS, ok := cutLast(rest)
	if !ok || id == "" {
		return "", 0, time.Time{}, false
	}
	gen, err1 := strconv.Atoi(genS)
	unix, err2 := strconv.ParseInt(issuedS, 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, time.Time{}, false
	}
	return id, gen, time.Unix(unix, 0), true
}
