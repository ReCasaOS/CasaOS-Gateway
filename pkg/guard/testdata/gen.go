//go:build ignore

// Writes the MMDB fixtures of the geo tests. Needs github.com/maxmind/mmdbwriter, which the
// module does not require: run it from a scratch module, e.g.
//
//	cp gen.go /tmp/gen/main.go && cd /tmp/gen && go mod init gen && go mod tidy && go run . <testdata dir>
package main

import (
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func write(path, typ string, rows map[string]mmdbtype.Map) {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		panic(err)
	}
	for cidr, v := range rows {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, v); err != nil {
			panic(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		panic(err)
	}
}

func country(cc string) mmdbtype.Map {
	return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(cc)}}
}

func asn(n uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n), "autonomous_system_organization": mmdbtype.String(org)}
}

func main() {
	dir := os.Args[1]
	write(filepath.Join(dir, "country.mmdb"), "DBIP-Country-Lite", map[string]mmdbtype.Map{
		"192.0.2.0/24": country("FR"), "198.51.100.0/24": country("DE")})
	write(filepath.Join(dir, "country-swapped.mmdb"), "DBIP-Country-Lite", map[string]mmdbtype.Map{
		"192.0.2.0/24": country("ES")})
	write(filepath.Join(dir, "asn.mmdb"), "DBIP-ASN-Lite", map[string]mmdbtype.Map{
		"192.0.2.0/24": asn(3215, "Orange"), "198.51.100.0/24": asn(3320, "Deutsche Telekom")})
}
