package proxyproto

import (
	"net"
	"time"
)

type conn struct {
	net.Conn
	remote net.Addr
}

func (c *conn) RemoteAddr() net.Addr { return c.remote }

type listener struct {
	net.Listener
	ready  chan net.Conn // never closed: handshakes may still send on it
	closed chan struct{} // closed once inner.Accept has failed
	err    error         // written before closed is closed, read after it
}

// Listen wraps inner: each accepted connection must start with a PROXY v2 header within headerTimeout,
// read in its own goroutine so a slow one never blocks Accept; the returned connections report the
// header's source as RemoteAddr. Connections with no/invalid header or nil addresses are closed silently.
func Listen(inner net.Listener, headerTimeout time.Duration) net.Listener {
	l := &listener{Listener: inner, ready: make(chan net.Conn), closed: make(chan struct{})}
	go func() {
		for {
			c, err := inner.Accept()
			if err != nil {
				l.err = err
				close(l.closed)
				return
			}
			go l.handshake(c, headerTimeout)
		}
	}()
	return l
}

func (l *listener) handshake(c net.Conn, timeout time.Duration) {
	c.SetReadDeadline(time.Now().Add(timeout))
	src, _, err := ReadV2(c)
	if err != nil || src == nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	select {
	case l.ready <- &conn{Conn: c, remote: src}:
	case <-l.closed:
		c.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.closed:
		return nil, l.err
	}
}
