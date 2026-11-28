//go:build !windows && !darwin

package main

import (
	"context"
	"errors"
)

func revealEnvironmentDiagnostics(context.Context, string) error {
	return errors.New("WINDOWS_OR_MACOS_REQUIRED")
}
