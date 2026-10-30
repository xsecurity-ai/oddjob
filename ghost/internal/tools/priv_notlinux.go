//go:build !linux

package tools

// linuxEffectiveNetRaw has nothing to answer off Linux. The second
// return is "do we know", and saying no here leaves the caller on its
// existing per-platform reasoning rather than inventing an answer.
func linuxEffectiveNetRaw() (bool, bool) { return false, false }

// linuxEffectiveBindService, ditto. Off Linux the capability model is
// different or absent, and "unknown" keeps the caller from reporting
// a Windows host as unable to bind 443 when it is perfectly able to.
func linuxEffectiveBindService() (bool, bool) { return false, false }
