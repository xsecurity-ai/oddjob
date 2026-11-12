//go:build !linux

package agent

import (
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/client"
)

// resourceSampler on a platform without /proc. The agent still reports
// the run's duration — that is all any platform can say for free — and
// leaves CPU, memory and network unset so the server stores them as
// unknown rather than zero (which would read as "used nothing").
type resourceSampler struct {
	started time.Time
}

func (s *resourceSampler) begin() error {
	s.started = time.Now()
	return nil
}

func (s *resourceSampler) stop() *client.Resource {
	return &client.Resource{DurationSec: time.Since(s.started).Seconds()}
}
