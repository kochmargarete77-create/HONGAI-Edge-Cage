//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

func revealEnvironmentDiagnostics(ctx context.Context, root string) error {
	directory, err := validateEnvironmentDiagnosticsDirectory(root)
	if err != nil {
		return err
	}
	request, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// open requests Finder activation and then exits; Finder itself is neither
	// spawned under this context nor terminated when the request completes.
	if exec.CommandContext(request, "/usr/bin/open", directory).Run() != nil {
		return errors.New("DIAGNOSTICS_REVEAL_FAILED")
	}
	return nil
}
