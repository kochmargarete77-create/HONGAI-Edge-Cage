//go:build !windows && !darwin

package main

import "errors"

func verifyOfficialInstaller(string) error { return errors.New("ONLY_WINDOWS_AND_MACOS_SUPPORTED") }
