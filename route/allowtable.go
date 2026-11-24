package route

import (
	"net/http"
	"path"
	"strings"

	"github.com/ReCasaOS/CasaOS-Common/external"
)

// kind says who may make the calls of a row of allowTable.
type kind string

const (
	public kind = "public" // anybody, with or without a token
	base   kind = "base"   // any signed-in account
	// files is an account given at least one folder of Files (external.FilesRight). The
	// Gateway does not see the paths of a call (bodies, multipart uploads): the core confines
	// every path to the account's folders, and a write to its read-and-write ones.
	files kind = "files"
)

// module is a row opened by the right of that name.
func module(name string) kind { return kind("module:" + name) }

type rule struct {
	Method, Pattern string
	Kind            kind
}

// allowTable is every call an account of role user may make; anything else is refused to it,
// reads and websockets included. A pattern is matched with path.Match, so `*` is one path segment.
// A GET row also opens HEAD. Each row was added after reading its handler (for the apps, with the
// visibility tests of app management): a route that acts, opens an interactive channel, sends
// traffic out of the box or hands out a secret is not here, even as a GET. testdata/ui-calls.txt lists what the dashboard calls in a user's session, and
// testdata/routes.txt the routes the services register; the tests hold the table to both.
var allowTable = []rule{
	// signing in, before there is a session
	{"GET", "/v1/users/status", public},                  // the login page: initialised or not, which login page
	{"POST", "/v1/users/login", public},                  // signing in
	{"POST", "/v1/users/2fa/verify", public},             // the second step of signing in
	{"POST", "/v1/users/refresh", public},                // a new access token for a refresh token, sent with the expired one
	{"POST", "/v1/users/register", public},               // the first account, with the key of the first start
	{"GET", "/v1/users/image", public},                   // the login page's avatar and wallpaper, from the account folders
	{"GET", "/v1/sys/version/current", public},           // the core's version as text: scripts wait on it to see the core up
	{"GET", "/v1/fleet/tunnel", public},                  // a member box's tunnel, which proves itself with its own code
	{"GET", "/v1/recover/*/*", public},                   // the browser's way back from a cloud sign-in (type/state), checked against the box's state
	{"POST", "/v2/app_management/git/*/webhook", public}, // a git forge's delivery, which proves itself with the app's secret
	{"POST", "/v2/mcp/server", public},                   // the MCP endpoint, which checks its own token

	// the account itself
	{"GET", "/v1/users/current", base},
	{"PUT", "/v1/users/current", base},
	{"PUT", "/v1/users/current/password", base},
	{"POST", "/v1/users/2fa/setup", base},
	{"POST", "/v1/users/2fa/enable", base},
	{"POST", "/v1/users/2fa/disable", base},
	{"GET", "/v1/users/current/custom/*", base}, // its preferences: dashboard, wallpaper, widgets, favourites
	{"POST", "/v1/users/current/custom/*", base},
	{"DELETE", "/v1/users/current/custom/*", base},
	{"POST", "/v1/users/current/image/*", base}, // its wallpaper, uploaded into its own folder
	{"PUT", "/v1/users/current/image/*", base},
	{"DELETE", "/v1/users/current/image", base},
	{"GET", "/v1/users/avatar", base},
	{"PUT", "/v1/users/avatar", base},

	// the apps, as the visibility lets the account see them (app management filters each answer)
	{"GET", "/v2/app_management/web/appgrid", base},        // the dashboard's apps
	{"GET", "/v2/app_management/compose", base},            // the apps of the app launching setting, secrets left out
	{"GET", "/v2/app_management/container/*/detail", base}, // an app's details, environment values left out
	{"GET", "/v2/app_management/stats", base},              // Statistics: the list
	{"GET", "/v2/app_management/stats/*", base},            // Statistics: one series
	{"GET", "/v2/app_management/stats/*/alerts", base},     // Statistics: the alert rules, read
	{"GET", "/v2/app_management/logs/apps", base},          // Logs: the apps
	{"GET", "/v2/app_management/logs", base},               // Logs: the history
	{"GET", "/v2/app_management/logs/events", base},        // Logs: the events
	{"GET", "/v2/app_management/logs/settings", base},      // Logs: retention and size, the probe that shows the Logs card
	{"GET", "/v2/app_management/logs/export", base},        // Logs: one day's file
	{"GET", "/v2/app_management/logs/stream", base},        // Logs: the live lines (websocket, token in the query)

	// the modules: each opens reads only, with the right of its name (external.RightsOf). Kept out even with the right:
	// the VM console and the ISO and download lists, the restic password and the files of a backup, the fleet's
	// relay, the box's raw logs and terminal, the files, and anything that is not a GET.
	{"GET", "/v1/sys/utilization", module("system")},     // load, memory, network, system disk (core)
	{"GET", "/v1/container/usage", module("system")},     // the containers' load, hidden apps left out (app management)
	{"GET", "/v1/sys/stats", module("system")},           // Statistics: the machine (core)
	{"GET", "/v1/sys/stats/*", module("system")},         // Statistics: its series
	{"GET", "/v1/sys/stats/*/alerts", module("system")},  // Statistics: its alert rules, read
	{"GET", "/v1/disks", module("storage")},              // the drives and their SMART health (local storage)
	{"GET", "/v1/disks/raid", module("storage")},         // the RAID arrays, as the kernel shows them
	{"GET", "/v1/disks/snapraid", module("storage")},     // SnapRAID: set up or not, its last runs
	{"GET", "/v1/disks/zfs", module("storage")},          // the ZFS pools and datasets
	{"GET", "/v1/storage", module("storage")},            // the storages and their volumes
	{"GET", "/v2/virt_management/host", module("vm")},    // libvirt there or not, CPUs, memory, network (no secret)
	{"GET", "/v2/virt_management/vms", module("vm")},     // the VMs and their state
	{"GET", "/v2/virt_management/vms/*", module("vm")},   // one VM; its console is /vms/*/console, not this row
	{"GET", "/v2/virt_management/stats", module("vm")},   // Statistics: the VMs
	{"GET", "/v2/virt_management/stats/*", module("vm")}, // Statistics: one VM's series
	{"GET", "/v2/virt_management/stats/*/alerts", module("vm")},
	{"GET", "/v2/app_management/backup/runs", module("backups")},         // the history, hidden apps left out
	{"GET", "/v2/app_management/backup/schedules", module("backups")},    // the schedules, hidden apps left out
	{"GET", "/v2/app_management/backup/destinations", module("backups")}, // the destinations' names only
	{"GET", "/v2/app_management/backup/running", module("backups")},      // what runs now, hidden apps left out
	{"GET", "/v2/app_management/operations", module("backups")},          // what runs on the apps now, hidden apps left out
	{"GET", "/v1/fleet", module("fleet")},                                // the role and the boxes, never a key; no relay call

	// Files, in the folders the owner gave the account (CasaOS#168). Kept out: the trash (it holds
	// what every account deleted), the transfer between devices (/v1/file/ws, /peers), cancelling
	// a copy (one id, or 0 for every copy of the box), the cloud drives, Samba, the search, and
	// the older upload (/v1/file/upload): the dashboard sends files by /v2/casaos/file/upload.
	{"GET", "/v1/file/roots", files},          // the account's folders, and which it may write
	{"GET", "/v1/folder", files},              // a folder's entries
	{"GET", "/v1/folder/size", files},         // a folder's size
	{"GET", "/v1/folder/count", files},        // how many entries
	{"GET", "/v1/file", files},                // one file, downloaded
	{"GET", "/v3/file", files},                // one file, downloaded (token in the query)
	{"GET", "/v1/file/content", files},        // a text file, read
	{"GET", "/v1/batch", files},               // files and folders, downloaded as one archive
	{"GET", "/v1/image", files},               // a thumbnail
	{"POST", "/v1/file", files},               // a new file
	{"PUT", "/v1/file", files},                // a text file, saved
	{"PUT", "/v1/file/name", files},           // a file renamed
	{"POST", "/v1/folder", files},             // a new folder
	{"PUT", "/v1/folder/name", files},         // a folder renamed
	{"GET", "/v2/casaos/file/upload", files},  // the dashboard's uploader: a chunk, asked about
	{"POST", "/v2/casaos/file/upload", files}, // the dashboard's uploader: a chunk
	{"POST", "/v1/batch/task", files},         // a copy or a move
	{"DELETE", "/v1/batch", files},            // a deletion, or a move to the trash
}

func matches(pattern, p string) bool {
	ok, _ := path.Match(pattern, p)
	return ok
}

// allowedBy says whether a row of allowTable that open says yes to opens this call. p is the
// escaped path, as the services route on it (tablePath). A trailing slash is taken only by a row
// that ends in a parameter, which the service gives the rest of the path; on any other row it
// would land on a sibling route with a parameter in that place.
func allowedBy(method, p string, open func(kind) bool) bool {
	trailing := len(p) > 1 && strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	for _, r := range allowTable {
		if trailing && !strings.HasSuffix(r.Pattern, "*") {
			continue
		}
		if (r.Method == method || r.Method == http.MethodGet && method == http.MethodHead) && matches(r.Pattern, p) && open(r.Kind) {
			return true
		}
	}
	return false
}

func isPublic(k kind) bool { return k == public }

// userMayCall says whether an account of role user, with these rights, may make this call (p as
// allowedBy takes it).
func userMayCall(method, p string, rights map[string]bool) bool {
	return allowedBy(method, p, func(k kind) bool {
		name, isModule := strings.CutPrefix(string(k), "module:")
		return k == public || k == base || isModule && rights[name] || k == files && rights[external.FilesRight]
	})
}
