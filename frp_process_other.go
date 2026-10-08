//go:build !linux

package main

import "os/exec"

// Other platforms use explicit Close. A service manager should terminate the
// complete process tree after abnormal supervisor termination.
func setFRPProcessAttributes(_ *exec.Cmd) {}
