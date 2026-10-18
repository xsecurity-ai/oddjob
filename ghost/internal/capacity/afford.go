package capacity

import "sort"

// What one task of each kind needs resident, in MB.
//
// Measured, not guessed, and the reason this file exists: nuclei
// peaks at 185 MB merely LOADING the CVE template set and exiting --
// `/usr/bin/time -v nuclei -tags cve -severity critical,high -tl` on
// one of our own agents, before a single request is sent. That cost
// is template compilation, so it is fixed: `-c 1` is the gentlest
// pacing there is and it does not move the number at all.
//
// A 458 MB droplet reporting 143 MB available therefore cannot run
// nuclei however politely it is asked, and a host that cannot hold a
// task has not failed it -- it is the wrong host for it. Pacing
// answers "how hard"; this answers "at all".
//
// Kinds absent from this map are unconstrained. The light tools --
// nmap, httpx, gobuster, katana, portscan -- run in tens of
// megabytes, and inventing a figure for each would be the guess this
// map exists to avoid.
var kindMemMB = map[string]int{
	// 185 measured, rounded up for the scan itself: sockets, response
	// bodies and matcher state on top of the compiled templates.
	"nuclei":      256,
	"nuclei_tech": 256,
	// Measured at 438 MB resident on one of our ghosts, which is
	// where `taskMemMB`'s "safe side of amass" figure came from.
	"amass": 512,
	// A headless Chromium, which is the heaviest thing this agent
	// can be asked to do.
	//
	// Measured, and the measurement is a FLOOR rather than the
	// figure. This agent's own runner, capturing a page inside the
	// ghost image with the same `--cap-drop=ALL` the fleet runs
	// with, read from the container's `memory.peak`:
	//
	//	1 GB limit   430 MB peak
	//	384 MB limit 204 MB peak, capture fine
	//	256 MB limit 204 MB peak, capture fine
	//
	// The first number is mostly reclaimable page cache -- chromium
	// is 376 MB of files and the cgroup counts them as they are read
	// -- which is why squeezing the limit does not break the
	// capture. The working set for that page is about 200 MB.
	//
	// The figure is 512 because 200 MB is the cheapest possible case
	// and a real engagement is not it. The page in that test loaded
	// nothing: no images, no fonts, no third-party scripts, no
	// video, and a renderer's memory is almost entirely the page's.
	// A single-page application on a client's estate routinely costs
	// several times a static page, and the agent is holding up to
	// 24 MB of PNG on top of it, which the JSON encode before
	// posting transiently doubles.
	//
	// Erring high is the cheap direction here. Too high and a 1 GB
	// box is not offered screenshots it could probably have taken;
	// too low and the OOM killer takes the agent, with it the scan
	// it was running, and -- as this fleet has already seen once --
	// the host's ability to complete an SSH banner exchange.
	//
	// So: measured on a page built to be cheap, and sized for one
	// that is not. What would replace the estimate with a figure is
	// the same thing that produced the nuclei and amass numbers --
	// a capture of a real client-estate page on a real ghost, watched
	// while it runs.
	"screenshot": 512,
}

// Unaffordable lists the task kinds this host cannot currently hold.
//
// Reported on the heartbeat so the SERVER skips them when choosing
// work, rather than the agent taking one and handing it back. Handing
// it back would be a livelock: the task returns to the pool, the same
// small host takes it again, and the queue spins. The existing
// `_has_tool` and `_needs_privilege` checks leave a candidate queued
// for an agent that can take it, and this is the same shape of answer
// for the same reason.
//
// Unknown memory reports nothing unaffordable. An agent on a platform
// whose figures cannot be read must keep working -- the same rule
// `assess` and `pace` already follow, because a measurement gap
// should not become an outage.
func Unaffordable(availMB int) []string {
	if availMB <= 0 {
		return nil
	}
	// Against what is left after the reserve, not against the raw
	// figure: spending the last megabyte is the condition the whole
	// package exists to avoid, and the OOM killer takes the agent
	// rather than the scanner.
	budget := availMB - reserveMemMB
	var out []string
	for kind, need := range kindMemMB {
		if need > budget {
			out = append(out, kind)
		}
	}
	// Stable, so a heartbeat that says the same thing looks the same.
	sort.Strings(out)
	return out
}

// CannotRun is Unaffordable for this host, read now.
func CannotRun() []string { return Unaffordable(availableMemMB()) }
