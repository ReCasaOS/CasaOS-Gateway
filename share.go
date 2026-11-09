package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"go.uber.org/zap"

	"github.com/ReCasaOS/CasaOS-Gateway/common"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/proxyproto"
)

// serveShare listens on 127.0.0.1:0 for the tunnel's visitor connections (PROXY v2, then TLS with
// tlsCfg), serves h on them and writes the address to <runtimePath>/share.addr. It returns the server
// so a test can Close it.
func serveShare(runtimePath string, tlsCfg *tls.Config, h http.Handler) (*http.Server, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(localhost, "0"))
	if err != nil {
		return nil, err
	}

	path, err := writeAddressFile(runtimePath, common.ShareAddrFilename, ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, err
	}

	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute, // the only listener facing strangers: an idle keep-alive would pin a tunnel stream
	}

	go func() {
		err := server.Serve(tls.NewListener(proxyproto.Listen(ln, 5*time.Second), tlsCfg))
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error when serving shared apps", zap.Error(err), zap.String("address", ln.Addr().String()))
		}
	}()

	logger.Info("Share listener is listening...", zap.String("address", ln.Addr().String()), zap.String("filepath", path))

	return server, nil
}
