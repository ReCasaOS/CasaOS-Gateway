package route

import "syscall"

// manifestOpenFlags: never follow a symlink, never wait on a FIFO.
const manifestOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
