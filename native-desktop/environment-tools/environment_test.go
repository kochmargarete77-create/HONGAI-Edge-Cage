package main

import (
	"strings"
	"testing"
)

func TestPlatformSpecificEnvironmentOverlay(t *testing.T) {
	base := []string{"Path=original", "OTHER=preserved", "=C:=C:\\working"}
	override := map[string]string{"PATH": "approved", "EXTRA": "retained"}
	win := mergedEnvironment(base, override, true)
	pathCount := 0
	for _, entry := range win {
		if strings.HasPrefix(strings.ToUpper(entry), "PATH=") {
			pathCount++
			if entry != "PATH=approved" {
				t.Fatal("WINDOWS_PATH_OVERRIDE_LOST")
			}
		}
	}
	if pathCount != 1 || !strings.Contains(strings.Join(win, "\n"), "=C:=C:\\working") {
		t.Fatal("WINDOWS_ENVIRONMENT_IDENTITY_OR_DRIVE_ENTRY_LOST")
	}
	mac := strings.Join(mergedEnvironment(base, override, false), "\n")
	if !strings.Contains(mac, "Path=original") || !strings.Contains(mac, "PATH=approved") || !strings.Contains(mac, "OTHER=preserved") {
		t.Fatal("MAC_CASE_SENSITIVE_ENVIRONMENT_CHANGED")
	}
}
