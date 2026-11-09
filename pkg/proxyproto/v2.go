// Package proxyproto reads and writes the PROXY protocol v2 header the relay
// puts in front of each visitor connection it forwards into the tunnel.
package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const sig = "\r\n\r\n\x00\r\nQUIT\n"

// ErrNotProxy means the stream does not start with a PROXY v2 header.
var ErrNotProxy = errors.New("not a PROXY protocol v2 header")

// ReadV2 reads exactly one PROXY v2 header from r (io.ReadFull, no over-read). A LOCAL command or a
// non-TCP family yields nil addresses and no error. Not a PROXY v2 signature → ErrNotProxy.
func ReadV2(r io.Reader) (src, dst *net.TCPAddr, err error) {
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, nil, err
	}
	if string(h[:12]) != sig || h[12]>>4 != 2 {
		return nil, nil, ErrNotProxy
	}
	body := make([]byte, binary.BigEndian.Uint16(h[14:16]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	if h[12]&0xf != 1 { // LOCAL: no address
		return nil, nil, nil
	}
	var ipLen int
	switch h[13] {
	case 0x11:
		ipLen = net.IPv4len
	case 0x21:
		ipLen = net.IPv6len
	default:
		return nil, nil, nil
	}
	if len(body) < 2*ipLen+4 {
		return nil, nil, fmt.Errorf("PROXY v2 address block too short: %d bytes", len(body))
	}
	ports := body[2*ipLen:]
	src = &net.TCPAddr{IP: net.IP(append([]byte(nil), body[:ipLen]...)), Port: int(binary.BigEndian.Uint16(ports))}
	dst = &net.TCPAddr{IP: net.IP(append([]byte(nil), body[ipLen:2*ipLen]...)), Port: int(binary.BigEndian.Uint16(ports[2:]))}
	return src, dst, nil
}

// WriteV2 writes a PROXY-command TCP header (IPv4 or IPv6 by src's family); tests and the core's fakes use it.
func WriteV2(w io.Writer, src, dst *net.TCPAddr) error {
	fam, s, d := byte(0x11), src.IP.To4(), dst.IP.To4()
	if s == nil || d == nil {
		fam, s, d = 0x21, src.IP.To16(), dst.IP.To16()
	}
	if s == nil || d == nil {
		return errors.New("PROXY v2: invalid address")
	}
	b := append([]byte(sig), 0x21, fam, 0, 0)
	b = append(b, s...)
	b = append(b, d...)
	b = binary.BigEndian.AppendUint16(b, uint16(src.Port))
	b = binary.BigEndian.AppendUint16(b, uint16(dst.Port))
	binary.BigEndian.PutUint16(b[14:16], uint16(len(b)-16))
	_, err := w.Write(b)
	return err
}
