//go:build linux

package agent

import "golang.org/x/sys/unix"

// reapOnce collects any reparented children the kernel has marked dead.
// Returns how many were reaped.
func reapOnce() int {
	n := 0
	for {
		var st unix.WaitStatus
		pid, err := unix.Wait4(-1, &st, unix.WNOHANG, nil)
		if pid <= 0 || err != nil {
			break
		}
		n++
	}
	return n
}
