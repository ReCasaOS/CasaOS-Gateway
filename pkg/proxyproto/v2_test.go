package proxyproto

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
)

func tcp(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestReadV2RoundTrip(t *testing.T) {
	for _, c := range []struct{ src, dst string }{
		{"203.0.113.9:4444", "10.0.0.1:443"},
		{"[2001:db8::1]:5555", "[2001:db8::2]:443"},
	} {
		var buf bytes.Buffer
		if err := WriteV2(&buf, tcp(t, c.src), tcp(t, c.dst)); err != nil {
			t.Fatal(err)
		}
		buf.WriteString("hello")

		src, dst, err := ReadV2(&buf)
		if err != nil {
			t.Fatalf("%s: ReadV2: %v", c.src, err)
		}
		if src.String() != c.src || dst.String() != c.dst {
			t.Fatalf("got %v -> %v, want %s -> %s", src, dst, c.src, c.dst)
		}
		if rest := buf.String(); rest != "hello" {
			t.Fatalf("bytes after the header = %q, want %q", rest, "hello")
		}
	}
}

func TestReadV2RejectsOtherBytes(t *testing.T) {
	_, _, err := ReadV2(strings.NewReader("GET / HTTP/1.1\r\n"))
	if !errors.Is(err, ErrNotProxy) {
		t.Fatalf("err = %v, want ErrNotProxy", err)
	}
}

func TestReadV2LocalCommandHasNoAddress(t *testing.T) {
	hdr := append([]byte(sig), 0x20, 0x00, 0, 0)
	src, dst, err := ReadV2(bytes.NewReader(hdr))
	if src != nil || dst != nil || err != nil {
		t.Fatalf("got %v, %v, %v; want nil, nil, nil", src, dst, err)
	}
}
