//go:build !linux

package route

// manifestOpenFlags: the gateway ships for Linux only; elsewhere (a developer's tests) the
// regular-file check after opening still holds.
const manifestOpenFlags = 0
