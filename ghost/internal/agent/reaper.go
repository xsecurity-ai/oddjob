package agent

import (
	"context"
	"log"
	"time"
)

// reapChildren reaps orphaned child processes.
//
// When the ghost runs as PID 1 in a container, any process it spawns
// that outlives its direct parent (e.g. Chrome's renderer and GPU
// children after chromedp kills the main browser process) is
// reparented to PID 1. The kernel will not free a zombie's entry from
// /proc until someone calls wait(2) on it, and Go's runtime only does
// that for processes started via os/exec — not for ones that were
// reparented after their original parent died.
//
// Without this, every screenshot task leaks ~15–20 zombie threads
// ([chrome], [chrome_crashpad]) that accumulate until the container is
// restarted. Each one holds a small amount of kernel memory and shows
// up in ps as State: Z with PPid: 1.
//
// The reaper polls wait4(-1, WNOHANG) on a timer. A 30-second interval
// is more than fast enough: zombies from a screenshot task appear within
// milliseconds of the allocator context cancelling, and 30 seconds is
// negligible compared to the hours or days a ghost runs between tasks.
func (a *Agent) reapChildren(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			n := reapOnce()
			if n > 0 {
				log.Printf("reaped %d orphaned child process(es)", n)
			}
		}
	}
}
