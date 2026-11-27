//go:build !windows && !darwin

package main

import (
	"context"
	"errors"
)

func discoverOfficialClient(context.Context) (OfficialClient, string, error) {
	return OfficialClient{}, "", errors.New("WINDOWS_OR_MACOS_REQUIRED")
}
func launchOfficialClient(context.Context, OfficialClient) error {
	return errors.New("WINDOWS_OR_MACOS_REQUIRED")
}
func openEnvironmentBrowser(string) error           { return errors.New("WINDOWS_OR_MACOS_REQUIRED") }
func defaultEnvironmentRoot() (string, error)       { return "", errors.New("WINDOWS_OR_MACOS_REQUIRED") }
func writeEnvironmentLauncher(string, string) error { return errors.New("WINDOWS_OR_MACOS_REQUIRED") }
func environmentProcessAlive(int) bool              { return true }

func preserveEnvironmentOrigin(string, string) error { return errors.New("WINDOWS_OR_MACOS_REQUIRED") }
func environmentTransitionGuard(string) (func(), error) {
	return nil, errors.New("WINDOWS_OR_MACOS_REQUIRED")
}

func secureEnvironmentDataRoot(string) error { return errors.New("WINDOWS_OR_MACOS_REQUIRED") }
