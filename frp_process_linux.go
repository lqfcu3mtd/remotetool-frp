//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func setFRPProcessAttributes(cmd *exec.Cmd) {
	// Prevent an orphaned tunnel if the supervisor is terminated ungracefully.
	// Linux delivers this when the creating OS thread exits; normal shutdown
	// still uses Close and waits for the child before removing its config.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
