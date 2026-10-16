package agent

import "os"

func hostname() (string, error) { return os.Hostname() }
