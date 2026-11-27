//go:build darwin

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacEnvironmentTimeZoneAndExecutableMetadata(t *testing.T) {
	for p, want := range map[string]string{"/private/var/db/timezone/zoneinfo.default/America/Los_Angeles": "America/Los_Angeles", "/var/db/timezone/zoneinfo/America/New_York": "America/New_York", "/usr/share/zoneinfo/posix/America/Chicago": "America/Chicago", "/usr/share/zoneinfo/Etc/UTC": "Etc/UTC", "/no-zone-here": "UNKNOWN"} {
		if macSystemTimeZonePath(p) != want {
			t.Fatal("timezone file mapping damaged")
		}
	}
	for _, name := range []string{"Claude", "Claude Desktop"} {
		if !validMacBundleExecutableName(name) {
			t.Fatal("normal bundle executable rejected")
		}
	}
	for _, name := range []string{"", ".", "..", "../outside", "path/to/executable", "path\\to\\executable", "bad\x00name"} {
		if validMacBundleExecutableName(name) {
			t.Fatal("unsafe bundle executable metadata accepted")
		}
	}
}

func TestMacEnvironmentLauncherLiteralCustomerPaths(t *testing.T) {
	p := testDirectory(t)
	root := filepath.Join(p, "中文 work '$HOME' $(must-not-run) !")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "echo '$HOME' fixture")
	if e := os.WriteFile(target, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := writeEnvironmentLauncher(root, target); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "/bin/sh", filepath.Join(root, "HONGAI-Environment.command")).Output()
	if e != nil {
		t.Fatal(e)
	}
	want := strings.Join([]string{"environment", "use", "--root", root, ""}, "\n")
	if string(out) != want {
		t.Fatal("launcher changed literal paths or arguments")
	}
	info, e := os.Stat(filepath.Join(root, "HONGAI-Environment.command"))
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("launcher is not private executable")
	}
}

func TestMacRuntimeQuarantineIsPreservedWithoutWeakening(t *testing.T) {
	p := testDirectory(t)
	source := filepath.Join(p, "source")
	target := filepath.Join(p, "target")
	strong := filepath.Join(p, "strong")
	unmarked := filepath.Join(p, "unmarked")
	for _, f := range []string{source, target, strong, unmarked} {
		if e := os.WriteFile(f, []byte("synthetic-not-an-executable"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mark := []byte("0081;65656565;Safari;HONGAI-SYNTHETIC-FIXTURE")
	other := []byte("0083;65656566;Safari;HONGAI-DIFFERENT-FIXTURE")
	if e := exec.CommandContext(ctx, "/usr/bin/xattr", "-w", "com.apple.quarantine", string(mark), source).Run(); e != nil {
		t.Fatal("fixture cannot create native quarantine marker")
	}
	if e := preserveEnvironmentOrigin(source, target); e != nil {
		t.Fatal(e)
	}
	b, present, e := readMacQuarantine(ctx, target)
	if e != nil || !present || !bytes.Equal(b, mark) {
		t.Fatal("quarantine marker lost")
	}
	if e = preserveEnvironmentOrigin(source, target); e != nil {
		t.Fatal("same quarantine marker not idempotent")
	}
	if e = exec.CommandContext(ctx, "/usr/bin/xattr", "-w", "com.apple.quarantine", string(other), strong).Run(); e != nil {
		t.Fatal(e)
	}
	if preserveEnvironmentOrigin(source, strong) == nil {
		t.Fatal("different existing destination origin overwritten")
	}
	if e = preserveEnvironmentOrigin(unmarked, strong); e != nil {
		t.Fatal(e)
	}
	b, present, e = readMacQuarantine(ctx, strong)
	if e != nil || !present || !bytes.Equal(b, other) {
		t.Fatal("unmarked source weakened destination quarantine")
	}
}

func TestMacEnvironmentOwnedRootAndNewChildrenArePrivate(t *testing.T) {
	parent := testDirectory(t)
	root := filepath.Join(parent, "environment")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(testDirectory(t), "unrelated")
	if e := os.Mkdir(outside, 0750); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	before, e := exec.CommandContext(ctx, "/bin/ls", "-lde", outside).Output()
	if e != nil {
		t.Fatal(e)
	}
	if e = exec.CommandContext(ctx, "/bin/chmod", "+a", "everyone allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit", root).Run(); e != nil {
		t.Fatal("inherited-ACL fixture could not be prepared")
	}
	if e = saveEnvironmentOwner(root); e != nil {
		t.Fatal(e)
	}
	if e = secureEnvironmentDataRoot(root); e != nil {
		t.Fatal(e)
	}
	child := filepath.Join(root, "private-child.json")
	if e = atomicReplace(child, []byte("synthetic-data")); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{root, child, filepath.Join(root, "environment-owner.json")} {
		info, e := os.Lstat(p)
		if e != nil {
			t.Fatal(e)
		}
		want := os.FileMode(0600)
		if p == root {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("component path does not have private mode")
		}
		out, e := exec.CommandContext(ctx, "/bin/ls", "-lde", p).Output()
		if e != nil {
			t.Fatal(e)
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 || strings.Contains(fields[0], "+") {
			t.Fatal("component path retained extended ACL")
		}
	}
	after, e := exec.CommandContext(ctx, "/bin/ls", "-lde", outside).Output()
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("unrelated directory changed")
	}
	unowned := testDirectory(t)
	if e = os.Chmod(unowned, 0750); e != nil {
		t.Fatal(e)
	}
	if secureEnvironmentDataRoot(unowned) == nil {
		t.Fatal("unowned directory accepted")
	}
	info, e := os.Stat(unowned)
	if e != nil || info.Mode().Perm() != 0750 {
		t.Fatal("rejected directory mode changed")
	}
}
