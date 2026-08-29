package pkg

import (
	"errors"
	"net/http"
	"time"

	http2 "github.com/IceWhaleTech/CasaOS-Common/utils/http"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
)

// ErrCheckURLNotOK is returned when a service answers with something other than
// 200 OK.
var ErrCheckURLNotOK = errors.New("check url did not return 200 OK")

// CheckURL reports whether the service at url answers with 200 OK.
func CheckURL(url string) error {
	response, err := http2.Get(url, 5*time.Second)
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
// retries run out, and returns the last error.
func CheckURLWithRetry(url string, retry uint) error {
	count := retry
	var err error

	for count >= 0 {
		logger.Info("Checking if service at URL is running...", zap.Any("url", url), zap.Any("retry", count))
		if err = CheckURL(url); err != nil {
			time.Sleep(time.Second)
			count--
			continue
		}
		break
	}

	return err
}
