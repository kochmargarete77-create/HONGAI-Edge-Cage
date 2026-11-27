//go:build !windows && !darwin

package main

import "errors"

func platformSeal([]byte, string) ([]byte, error) {
	return nil, errors.New("ONLY_NATIVE_WINDOWS_AND_MACOS_SUPPORTED")
}
func platformOpen([]byte, string) ([]byte, error) {
	return nil, errors.New("ONLY_NATIVE_WINDOWS_AND_MACOS_SUPPORTED")
}
