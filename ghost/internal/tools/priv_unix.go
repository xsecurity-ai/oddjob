//go:build !windows

package tools

func windowsElevated() bool { return false }
