package route

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

// A FIFO, a symlink and an oversized file among the manifests are skipped, never waited on, and
// the manifests beside them still read.
func TestModulePageSkipsOddFiles(t *testing.T) {
	env := newModuleEnv(t)
	elsewhere := filepath.Join(t.TempDir(), "real.json")
	assert.NilError(t, os.WriteFile(elsewhere, []byte(`{"gateway_route":"/v2/mcp"}`), 0o644))
	dir := withManifests(t, map[string]string{
		"wake_on_lan.json": wakeOnLan,
		"big.json":         `{"gateway_route":"/v2/mcp"}` + string(make([]byte, maxManifestBytes)),
	})
	assert.NilError(t, syscall.Mkfifo(filepath.Join(dir, "fifo.json"), 0o644))
	assert.NilError(t, os.Symlink(elsewhere, filepath.Join(dir, "link.json")))
	assert.NilError(t, os.Symlink("/dev/zero", filepath.Join(dir, "zero.json")))

	done := make(chan [2]int, 1)
	go func() {
		done <- [2]int{env.call(t, "GET", "/v1/wake_on_lan/", nil), env.call(t, "GET", "/v2/mcp/", nil)}
	}()
	select {
	case got := <-done:
		assert.Equal(t, got[0], 200) // the plain manifest beside them reads
		assert.Equal(t, got[1], 401) // the symlinked and the oversized ones do not
	case <-time.After(5 * time.Second):
		t.Fatal("reading the manifests hung")
	}
}
