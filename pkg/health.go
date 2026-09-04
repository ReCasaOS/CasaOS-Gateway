package pkg

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
)

// ErrCheckURLNotOK is returned when a service answers with something other than
// 200 OK.
var ErrCheckURLNotOK = errors.New("check url did not return 200 OK")

// checkClient probes a listener this process just opened. It does not verify
// certificates on purpose: the probe addresses the listener by its bind
// address, which no certificate can legitimately carry, and the request never
// leaves the host.
var checkClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // local liveness probe, see above
		},
	},
}

// CheckURL reports whether the service at url answers with 200 OK. It is a
// liveness probe for a local listener, not a security check: TLS certificates
// are not verified.
func CheckURL(url string) error {
	response, err := checkClient.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return ErrCheckURLNotOK
	}

	return nil
}

// CheckURLWithRetry polls url once a second until it answers 200 OK or the
// retries run out, and returns the last error. retry counts the retries after
// the first attempt, so the url is checked retry+1 times at most.
func CheckURLWithRetry(url string, retry uint) error {
	var err error

	// count is unsigned: stop on zero rather than after decrementing it, or it
	// underflows to a number of retries no listener will ever outlast.
	for count := retry; ; count-- {
		logger.Info("Checking if service at URL is running...", zap.Any("url", url), zap.Any("retry", count))
		if err = CheckURL(url); err == nil || count == 0 {
			return err
		}
		time.Sleep(time.Second)
	}
}
