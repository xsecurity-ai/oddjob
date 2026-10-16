//go:build !linux

package capacity

import "context"

// Not measured off Linux, and said rather than guessed.
//
// Both return Unknown, which `assess` treats as "do not block". That
// is the right default here: an agent on macOS or Windows is a
// developer's machine or a bridgehead, not one of the small
// memory-starved boxes this veto exists for, and refusing all work
// because a figure cannot be read would turn a measurement gap into
// an outage.
//
// The honest alternative — implementing this per platform — needs
// vm_stat parsing and a second sample on darwin and a WMI or
// PdhCollectQueryData call on Windows, and `availableMemMB` already
// shows what the darwin version of that costs. Worth doing if agents
// start living on those platforms; not worth guessing at now.

func memFreeFraction() float64 { return Unknown }

func cpuIdleFraction(_ context.Context) float64 { return Unknown }
