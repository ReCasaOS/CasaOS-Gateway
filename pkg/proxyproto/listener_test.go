package proxyproto

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func newListener(t *testing.T, timeout time.Duration) (net.Listener, string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, timeout)
	t.Cleanup(func() { ln.Close() })
	return ln, inner.Addr().String()
}

func dialWith(t *testing.T, addr, payload string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if payload != "" {
		if _, err := c.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func dialProxied(t *testing.T, addr, src, payload string) net.Conn {
	t.Helper()
	c := dialWith(t, addr, "")
	if err := WriteV2(c, tcp(t, src), tcp(t, "10.0.0.1:443")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	return c
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type accepted struct {
	c   net.Conn
	err error
}

func acceptAsync(ln net.Listener) <-chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()
	return ch
}

func TestListenReportsTheProxySource(t *testing.T) {
	ln, addr := newListener(t, time.Second)
	dialProxied(t, addr, "203.0.113.9:4444", "x")

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != "203.0.113.9:4444" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 'x' {
		t.Fatalf("read = %q, %v; want x", b, err)
	}
}

func TestSlowHeaderDoesNotBlockOthers(t *testing.T) {
	ln, addr := newListener(t, 2*time.Second)
	a := dialWith(t, addr, "")
	dialProxied(t, addr, "203.0.113.10:1", "b")

	select {
	case r := <-acceptAsync(ln):
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.c.Close()
		if got := r.c.RemoteAddr().String(); got != "203.0.113.10:1" {
			t.Fatalf("Accept returned %s, want B", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Accept blocked behind the silent connection")
	}

	a.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := a.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("silent connection read = %v, want EOF after the header timeout", err)
	}
}

func TestBadHeaderIsDropped(t *testing.T) {
	ln, addr := newListener(t, time.Second)
	bad := dialWith(t, addr, "GET / HTTP/1.1\r\n\r\n")
	pending := acceptAsync(ln)

	bad.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Unread bytes make the OS send RST instead of FIN on some platforms, so a reset counts as closed too.
	if _, err := bad.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("bad connection read = %v, want EOF or reset", err)
	}

	dialProxied(t, addr, "203.0.113.11:2", "")
	select {
	case r := <-pending:
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.c.Close()
		if got := r.c.RemoteAddr().String(); got != "203.0.113.11:2" {
			t.Fatalf("Accept returned %s, want the valid connection", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept never returned the valid connection")
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	ln, _ := newListener(t, time.Second)
	pending := acceptAsync(ln)
	ln.Close()
	select {
	case r := <-pending:
		if r.err == nil {
			t.Fatal("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked after Close")
	}
}
