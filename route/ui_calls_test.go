package route

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

// Every call the dashboard makes in a user's session reaches its service through the Gateway: with
// the token of a user without rights, and with no token for a public one.
func TestEveryUICallIsInTheTable(t *testing.T) {
	f, err := os.Open("testdata/ui-calls.txt")
	assert.NilError(t, err)
	defer f.Close()

	env := newReadOnlyEnv(t)
	user := map[string]string{"Authorization": env.token(t, userID)}
	calls := 0
	modules := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		assert.Equal(t, len(fields), 3, line)
		method, p, k := fields[0], fields[1], fields[2]
		calls++

		// a module's call: its right alone opens it, no other right and no token do
		if right, ok := strings.CutPrefix(k, "module:"); ok {
			id, known := rightIDs[right]
			assert.Assert(t, known, line)
			before := len(env.hits.list())
			assert.Equal(t, env.call(t, method, p, map[string]string{"Authorization": env.token(t, id)}), 200, line)
			assert.Equal(t, len(env.hits.list()), before+1, line)
			for other, otherID := range rightIDs {
				if other != right {
					assert.Equal(t, env.call(t, method, p, map[string]string{"Authorization": env.token(t, otherID)}), 403, line+" with "+other)
				}
			}
			assert.Equal(t, env.call(t, method, p, user), 403, line)
			assert.Equal(t, env.call(t, method, p, nil), 401, line)
			modules[right]++
			continue
		}
		assert.Assert(t, k == "public" || k == "base", line)

		before := len(env.hits.list())
		assert.Equal(t, env.call(t, method, p, user), 200, line)
		assert.Equal(t, len(env.hits.list()), before+1, line) // reached the service
		if k == "public" {
			assert.Equal(t, env.call(t, method, p, nil), 200, line)
		} else {
			assert.Equal(t, env.call(t, method, p, nil), 401, line)
		}
	}
	assert.NilError(t, scanner.Err())
	assert.Assert(t, calls > 0)
	for right := range rightIDs {
		assert.Assert(t, modules[right] > 0, "no call of the module %s", right)
	}
}
