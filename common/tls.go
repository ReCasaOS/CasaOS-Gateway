package common

import "crypto/tls"

// TLSConfig is the optional certificate the gateway serves with. Both fields
// empty means plain HTTP, which is the default and what CasaOS has always done.
//
// Where certificates come from: the administrator may supply a pair (this
// type); otherwise the gateway makes a self-signed one (SelfSigned). The gateway
// never runs ACME itself: the share certificate is obtained by the core (ACME
// DNS-01 through the relay) and only served here, by CertPicker.
type TLSConfig struct {
	CertFile string
	KeyFile  string
}

// Enabled reports whether the gateway should serve HTTPS.
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

// Scheme is the URL scheme the gateway answers on.
func (t TLSConfig) Scheme() string {
	if t.Enabled() {
		return "https"
	}

	return "http"
}

// Validate parses the key pair up front, so a bad certificate fails a reload
// instead of killing the serving goroutine once the listener has been swapped.
func (t TLSConfig) Validate() error {
	if !t.Enabled() {
		return nil
	}

	_, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)

	return err
}
