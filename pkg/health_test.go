package pkg

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckURL(t *testing.T) {
	t.Run("a 200 response means the service is up", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		if err := CheckURL(server.URL); err != nil {
			t.Fatalf("CheckURL() = %v, want nil", err)
		}
	})

	t.Run("a non-200 response is reported as not OK", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		if err := CheckURL(server.URL); !errors.Is(err, ErrCheckURLNotOK) {
			t.Fatalf("CheckURL() = %v, want ErrCheckURLNotOK", err)
		}
	})

	// This path used to dereference a nil response and panic, turning a
	// retryable "not up yet" into a crash of the whole gateway.
	t.Run("an unreachable address returns an error instead of panicking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := server.URL
		server.Close()

		if err := CheckURL(url); err == nil {
			t.Fatal("CheckURL() = nil, want a transport error")
		}
	})
}

// The gateway probes its own listener by bind address, so an HTTPS listener can
// never present a verifiable certificate. The probe has to tolerate that.
func TestCheckURLOverTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := CheckURL(server.URL); err != nil {
		t.Fatalf("CheckURL() over TLS = %v, want nil", err)
	}
}
