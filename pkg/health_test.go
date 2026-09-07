package pkg

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkly/CasaOS-Common/utils/logger"
)

// CheckURLWithRetry logs every attempt, and CasaOS-Common's logger dereferences a
// nil *zap.Logger until it is initialised. main does that at startup, tests have
// to do it themselves, as the route and service test packages already do.
func init() {
	logger.LogInitConsoleOnly()
}

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

// The retry count is a uint that used to be decremented past zero, so a listener
// that never answers kept the loop (and reloadGateway with it) running forever.
func TestCheckURLWithRetryGivesUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	done := make(chan error, 1)
	go func() { done <- CheckURLWithRetry(url, 1) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("CheckURLWithRetry() = nil, want the last error")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("CheckURLWithRetry() never gave up")
	}
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
