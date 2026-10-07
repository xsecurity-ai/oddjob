//go:build !linux && !darwin

package capacity

// availableMemMB is not implemented here. Zero means "unknown", and the
// assessment leaves memory out of its reasoning rather than inventing a
// number — on Windows the cores figure alone decides.
func availableMemMB() int { return 0 }
