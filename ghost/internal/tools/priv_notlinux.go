//go:build !linux

package tools

// linuxEffectiveNetRaw has nothing to answer off Linux. The second
// return is "do we know", and saying no here leaves the caller on its
// existing per-platform reasoning rather than inventing an answer.
func linuxEffectiveNetRaw() (bool, bool) { return false, false }
