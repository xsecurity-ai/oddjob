//go:build windows

package tools

import "golang.org/x/sys/windows"

// windowsElevated asks the token, rather than guessing from the
// username: "Administrator" without elevation is not elevated, and an
// ordinary user in an elevated prompt is.
func windowsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
