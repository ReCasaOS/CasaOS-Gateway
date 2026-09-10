# CasaOS Gateway

> **Not affiliated with IceWhale.** An independent, community-maintained distribution of CasaOS, not produced or endorsed by Shanghai IceWhale Technology Limited. CASAOS is their trademark, used here only to say what this is a release of. The original project is [IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS); report problems with this distribution at [ReCasaOS/CasaOS/issues](https://github.com/ReCasaOS/CasaOS/issues).

The gateway is the only CasaOS service bound to a public port. Every other component — the system API, app management, user accounts, the message bus, local storage — listens on loopback and registers a path prefix here; the gateway forwards each request to whichever service claimed the longest matching prefix. It also serves the dashboard's files.

This repository is part of **ReCasaOS**, a maintained release of the project after upstream [IceWhaleTech/CasaOS-Gateway](https://github.com/IceWhaleTech/CasaOS-Gateway) stopped shipping in 2025. It descends from [alvins82's fork](https://github.com/alvins82/CasaOS-Gateway), whose Ubuntu 26 fix to the setup script is still in here.

## What it runs

Three listeners, from one process:

- **The public port** — the proxy itself, plus `GET /ping`. Paths are matched longest first, so a route on `/v1/apps` is not swallowed by one on `/v1`. `X-Forwarded-For` and `X-Real-IP` are rewritten before forwarding, so a service behind the gateway sees the address the connection actually came from rather than one a client claimed.
- **The management API**, on `127.0.0.1` at a port the kernel assigns. `GET` and `POST /v1/gateway/routes` list and register routes; `GET` and `PUT /v1/gateway/port` read and change the public port. The two writes require a CasaOS JWT unless the request comes from loopback. The address is written to `/var/run/casaos/management.url`, which is how the other services find it, and the port endpoint is also proxied on the public port under `/v1/gateway/port`.
- **The static server**, on `127.0.0.1` at another assigned port, serving the dashboard from the directory given by `-w`, which the shipped systemd unit leaves at its default of `/var/lib/casaos/www`, and registered as the route `/`. Its address goes to `/var/run/casaos/static.url`.

Changing the port opens the new listener, waits for it to answer `/ping`, and stops the old one a second later so requests already in flight still get a response. Registered routes are kept in `/var/run/casaos/routes.json`.

## Install

Components are not installed individually. The installer places all of them:

```sh
curl -fsSL https://github.com/ReCasaOS/CasaOS-Install/releases/latest/download/install.sh | sudo bash
```

[CasaOS-Install](https://github.com/ReCasaOS/CasaOS-Install#readme) describes what a release contains and how it is built.

## Configuration

`/etc/casaos/gateway.ini`, written from [the sample](./build/sysroot/etc/casaos/gateway.ini.sample) on first start if it does not exist:

```ini
[common]
runtimepath=/var/run/casaos

[gateway]
port=
address=
tlscert=
tlskey=
```

`port` is the public port. Left empty, the service takes the first free port from 80–89, then 8080–8089, and writes its choice back to this file; changing the port from the dashboard rewrites it too.

`address` is the interface that port binds to. Empty, the default, binds every interface as dual-stack `[::]`. Set it to one address to keep the dashboard off an untrusted network without a firewall rule. The management and static listeners stay on `127.0.0.1` either way.

`tlscert` and `tlskey` are a certificate and private key you supply. With both set the gateway serves HTTPS, with neither it serves plain HTTP. Half a pair falls back to HTTP rather than leaving a box unreachable through the only thing that serves its UI.

The file is looked for in the working directory, then `./conf`, then `$CASAOS_CONFIG_PATH` if it is set, then `/etc/casaos`. Logs are written to `/var/log/casaos/gateway.log`.

A service behind this gateway should bind loopback only — `127.0.0.1`, or `::1` — since the gateway is the part meant to be reachable.

## What this fork changed

- **TLS with an administrator-supplied certificate**, the `tlscert` and `tlskey` keys above. The key pair is parsed before the listener is swapped, so a bad certificate fails the reload with an error instead of killing the serving goroutine once the old listener is already gone. There is no ACME and no self-signed generation: automatic issuance needs port 80 reachable from the internet or registrar credentials, which belongs in a reverse proxy. This covers the bring-your-own-certificate half of [CasaOS #1074](https://github.com/IceWhaleTech/CasaOS/issues/1074).
- **`address=`, binding the public port to one interface** (v0.4.41). Both bind sites were hard-wired to every interface before. The idea comes from [CasaOS-Gateway #56](https://github.com/IceWhaleTech/CasaOS-Gateway/issues/56), rewritten smaller: no state plumbing, and no `gateway.url` file, which nothing ever read and which the code had never written.
- **A health check that works.** Every branch of it was inverted: it reported success without looking at the status code, reported failure when the status *was* 200 OK, and dereferenced a nil response on the unreachable path, so a service that was not up yet panicked the gateway instead of being retried — and the retry loop never retried anything. It now lives in `pkg/`, with a test.
- **A release pipeline that can run here.** Upstream's workflow called an IceWhale reusable workflow needing Aliyun credentials and published to the `IceWhaleTech` organisation, so a fork could never cut a release. It is a self-contained job now: it runs the tests, cross-builds static binaries for amd64, arm64 and arm/v7, and publishes the tarballs with the `checksums.txt` the installer verifies against.
- **No geo-IP at install time.** `build/scripts/migration/script.d` ran `__get_download_domain` at top level, curling `ipconfig.io/country` and then `ifconfig.io/country_code` to pick a download mirror by country. `install.sh` runs every script in that directory on every install and every upgrade, so both services were contacted each time, before the script had even decided whether a migration was due — which, on anything but a pre-0.4 box, it never is. The migration tools now come from GitHub unconditionally, and the domain is a constant: it is not an environment knob either, because what it points at is downloaded and run as root without verification.
- **Ubuntu 26 setup**, inherited from alvins82. The setup script picks its per-distribution script by walking a candidate list — `ID/VERSION_CODENAME`, then `ID`, then each entry of `ID_LIKE` — and says which OS it could not place when none of them exists, in place of nested `pushd` fallbacks that did not resolve on Ubuntu 26.
- **Its own module path.** The Go module is `github.com/inkly/CasaOS-Gateway` and it builds against `github.com/inkly/CasaOS-Common v0.4.22`, so log lines, stack traces and `go version -m` on the shipped binary name this fork instead of the upstream that stopped shipping.

## Development

Go, as declared in `go.mod`. Build, vet and test:

```sh
go build ./...
go vet ./...
go test ./...
```

Running the binary from a checkout needs a `gateway.ini` it can find and a writable `runtimepath`; `go test` covers the config loading, the TLS configuration, the health check, the management routes and route persistence without either.

## Licence and credits

Apache License 2.0 — see [LICENSE](LICENSE), kept as upstream shipped it. It is the stock Apache text: neither the licence file nor any source file carries a copyright line, and none has been added here.

CasaOS and this gateway are the work of IceWhale and its contributors; the Ubuntu 26 setup fallback is [alvins82](https://github.com/alvins82/CasaOS-Gateway)'s. CasaOS is a mark of IceWhale, used here to say what this is a release of and nothing more.
