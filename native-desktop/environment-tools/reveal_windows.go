//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func revealEnvironmentDiagnostics(ctx context.Context, root string) error {
	directory, err := validateEnvironmentDiagnosticsDirectory(root)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("DIAGNOSTICS_REVEAL_CANCELLED")
	}
	windows := os.Getenv("WINDIR")
	if !filepath.IsAbs(windows) || strings.HasPrefix(windows, `\\`) {
		return errors.New("DIAGNOSTICS_FILE_MANAGER_UNAVAILABLE")
	}
	// A successful request must outlive the HTTP action's context. Explorer is
	// the visible user file manager, so never tie its lifetime to CommandContext.
	command := exec.Command(filepath.Join(windows, "explorer.exe"), directory)
	if command.Start() != nil {
		return errors.New("DIAGNOSTICS_REVEAL_FAILED")
	}
	go func() { _ = command.Wait() }()
	return nil
}
