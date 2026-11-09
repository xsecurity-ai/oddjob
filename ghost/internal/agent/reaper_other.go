//go:build !linux

package agent

// reapOnce is a no-op on non-Linux platforms. The ghost runs in
// containers (Linux) in production; the reaper exists for the PID-1
// zombie case that only applies there.
func reapOnce() int { return 0 }
