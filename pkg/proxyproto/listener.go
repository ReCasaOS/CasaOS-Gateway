package proxyproto

import (
	"net"
	"sync"
	"time"
)

type conn struct {
	net.Conn
	remote net.Addr
}

func (c *conn) RemoteAddr() net.Addr { return c.remote }

type listener struct {
	net.Listener
	ready     chan net.Conn
	done      chan struct{} // closed by Close, releases handshakes waiting to deliver
	closeOnce sync.Once
	err       error // written before ready is closed, read after it
}

// Listen wraps inner: each accepted connection must start with a PROXY v2 header within headerTimeout,
// read in its own goroutine so a slow one never blocks Accept; the returned connections report the
// header's source as RemoteAddr. Connections with no/invalid header or nil addresses are closed silently.
func Listen(inner net.Listener, headerTimeout time.Duration) net.Listener {
	l := &listener{Listener: inner, ready: make(chan net.Conn), done: make(chan struct{})}
	go func() {
		for {
			c, err := inner.Accept()
			if err != nil {
				l.err = err
				close(l.ready)
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
	case <-l.done:
		c.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	if c, ok := <-l.ready; ok {
		return c, nil
	}
	return nil, l.err
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}
