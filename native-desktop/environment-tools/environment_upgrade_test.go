package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnvironmentUpgradeKeepsOriginalSettingsAndCryptographicRoot(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	want := fixtureSettings()
	if e := saveEnvironmentSettings(root, want); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(root, "environment-settings.sealed"))
	newSource := filepath.Join(filepath.Dir(root), "new-source-runtime")
	if e := os.WriteFile(newSource, []byte("HONGAI_NEW_RUNTIME_UPDATE_FIXTURE"), 0700); e != nil {
		t.Fatal(e)
	}
	inputRoot := root
	if runtime.GOOS == "windows" {
		inputRoot = strings.ToUpper(root)
	}
	r, e := installEnvironment(inputRoot, newSource)
	if e != nil || r.Root != root {
		t.Fatalf("upgrade did not retain cryptographic root: %v", e)
	}
	after, _ := os.ReadFile(filepath.Join(root, "environment-settings.sealed"))
	if !bytes.Equal(before, after) {
		t.Fatal("upgrade rewrote saved settings")
	}
	resolved, e := environmentRoot(inputRoot, false)
	if e != nil || resolved != root {
		t.Fatal("existing owned path did not normalize to original root")
	}
	if got, e := loadEnvironmentSettings(resolved); e != nil || got != want {
		t.Fatal("upgrade lost saved configuration")
	}
}

func TestEnvironmentUnreadableSavedSettingsAreNeverOverwritten(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	p := filepath.Join(root, "environment-settings.sealed")
	want := []byte("CORRUPT_OR_WRONG_USER_ENCRYPTED_SETTINGS_FIXTURE")
	if e := os.WriteFile(p, want, 0600); e != nil {
		t.Fatal(e)
	}
	if e := saveEnvironmentSettings(root, fixtureSettings()); e == nil || e.Error() != "EXISTING_SETTINGS_UNREADABLE_RESTORE_OR_REVIEW_REQUIRED" {
		t.Fatal("unreadable settings were accepted as a fresh configuration")
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, want) {
		t.Fatal("recovery material changed")
	}
	s := newEnvironmentServer(root, "http://127.0.0.1:1", "fixture-session", environmentOperations{})
	defer s.cancel()
	if s.lastCode != "EXISTING_SETTINGS_UNREADABLE_RESTORE_OR_REVIEW_REQUIRED" {
		t.Fatal("unreadable settings were not surfaced in the management UI")
	}
	if s.configurationIssue != s.lastCode {
		t.Fatal("configuration issue would disappear during inventory refresh")
	}
}

func TestEnvironmentUpgradeWaitsForActiveWorkbenchWithoutChangingReceipt(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	before, _ := os.ReadFile(filepath.Join(root, "environment-receipt.json"))
	release, e := acquireEnvironmentLock(root, "workbench-active.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	source := filepath.Join(filepath.Dir(root), "upgrade-while-active")
	if e = os.WriteFile(source, []byte("NEW_UPGRADE_WHILE_ACTIVE_FIXTURE"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = installEnvironment(root, source); e == nil || e.Error() != "CLOSE_WORKBENCH_SERVICE_BEFORE_UPGRADE" {
		t.Fatal("new runtime was applied while old workbench was active")
	}
	after, _ := os.ReadFile(filepath.Join(root, "environment-receipt.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("blocked upgrade changed installed runtime receipt")
	}
	release()
	if _, e = installEnvironment(root, source); e != nil {
		t.Fatal("closed workbench did not permit the approved upgrade")
	}
}
