//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only the test executable contains this echo fixture. It never activates an
// application and can only write beneath the explicitly approved test root.
func init() {
	p := os.Getenv("HONGAI_PLATFORM_LAUNCHER_ECHO")
	if p == "" {
		return
	}
	root := os.Getenv("HONGAI_TEST_ROOT")
	rel, e := filepath.Rel(root, p)
	if e != nil || !filepath.IsAbs(root) || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		os.Exit(91)
	}
	b, e := json.Marshal(os.Args[1:])
	if e != nil || os.WriteFile(p, b, 0600) != nil {
		os.Exit(92)
	}
	os.Exit(0)
}

func TestWindowsEnvironmentHelperPreservesUnicodeAndCaseOverride(t *testing.T) {
	t.Setenv("hongai_environment_echo", "wrong-inherited-value")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := windowsEnvironmentCommand(ctx, `@{value=$env:HONGAI_ENVIRONMENT_ECHO}|ConvertTo-Json -Compress`, map[string]string{"HONGAI_ENVIRONMENT_ECHO": "中文路径验证"})
	out, e := c.Output()
	if e != nil {
		t.Fatal("native helper failed")
	}
	var result struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(out, &result) != nil || result.Value != "中文路径验证" {
		t.Fatal("helper damaged Unicode or retained stale environment value")
	}
	count := 0
	for _, v := range c.Env {
		if strings.HasPrefix(strings.ToUpper(v), "HONGAI_ENVIRONMENT_ECHO=") {
			count++
		}
	}
	if count != 1 {
		t.Fatal("case-insensitive duplicate environment variable retained")
	}
}

func TestWindowsEnvironmentLauncherLiteralCustomerPaths(t *testing.T) {
	p := testDirectory(t)
	root := filepath.Join(p, "中文 %HONGAI_FAKE% 100% ! & work")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "echo 中文 %HONGAI_FAKE% !.exe")
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(target, b, 0700); e != nil {
		t.Fatal(e)
	}
	if e = writeEnvironmentLauncher(root, target); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(p, "launcher-args.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe"), "/d", "/v:on", "/c", "HONGAI-Environment.cmd")
	c.Dir = root
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	c.Env = mergedEnvironment(os.Environ(), map[string]string{"HONGAI_PLATFORM_LAUNCHER_ECHO": output, "HONGAI_FAKE": "MUST_NOT_EXPAND"}, true)
	if e = c.Run(); e != nil {
		t.Fatal("launcher failed")
	}
	b, e = os.ReadFile(output)
	if e != nil {
		t.Fatal("launcher did not execute fixture")
	}
	var args []string
	if json.Unmarshal(b, &args) != nil || len(args) != 4 || args[0] != "environment" || args[1] != "use" || args[2] != "--root" || args[3] != root {
		t.Fatal("launcher changed customer path or arguments")
	}
}

func TestWindowsEnvironmentProfileCandidatesDoNotClaimActiveState(t *testing.T) {
	p := testDirectory(t)
	local := filepath.Join(p, "Local")
	roaming := filepath.Join(p, "Roaming")
	current := filepath.Join(local, "Claude-Data", "Claude_pzs8sxrjxfjjc")
	redirected := filepath.Join(local, "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude")
	for _, d := range []string{current, redirected, roaming} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	_ = os.WriteFile(filepath.Join(current, "config.json"), []byte("{}"), 0600)
	_ = os.WriteFile(filepath.Join(redirected, ".user-data-left.claude_pzs8sxrjxfjjc"), []byte("fixture-marker-only"), 0600)
	got, exists, selection := windowsClaudeProfileCandidate(local, roaming)
	if !exists || got != current || !strings.Contains(selection, "NOT_PROVEN_ACTIVE") {
		t.Fatal("directory presence was promoted to active-profile proof")
	}
	legacy := filepath.Join(roaming, "Claude")
	_ = os.Mkdir(legacy, 0700)
	_ = os.WriteFile(filepath.Join(legacy, "Local State"), []byte("{}"), 0600)
	_, _, selection = windowsClaudeProfileCandidate(local, roaming)
	if selection != "MULTIPLE_PROFILE_CANDIDATES_REVIEW_REQUIRED" {
		t.Fatal("multiple substantive profiles were hidden")
	}
}

func TestWindowsRuntimeOriginMarkerIsPreservedWithoutWeakening(t *testing.T) {
	p := testDirectory(t)
	source := filepath.Join(p, "source.exe")
	target := filepath.Join(p, "target.exe")
	strong := filepath.Join(p, "strong.exe")
	unmarked := filepath.Join(p, "unmarked.exe")
	for _, f := range []string{source, target, strong, unmarked} {
		if e := os.WriteFile(f, []byte("synthetic-not-an-executable"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	mark := []byte("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/fixture\r\n")
	strongMark := []byte("[ZoneTransfer]\r\nZoneId=4\r\n")
	if e := os.WriteFile(source+":Zone.Identifier", mark, 0600); e != nil {
		t.Fatal("fixture filesystem cannot preserve required Windows origin markers")
	}
	if e := preserveEnvironmentOrigin(source, target); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(target + ":Zone.Identifier")
	if e != nil || !bytes.Equal(b, mark) {
		t.Fatal("origin marker lost")
	}
	if e = preserveEnvironmentOrigin(source, target); e != nil {
		t.Fatal("same origin marker not idempotent")
	}
	if e = os.WriteFile(strong+":Zone.Identifier", strongMark, 0600); e != nil {
		t.Fatal(e)
	}
	if preserveEnvironmentOrigin(source, strong) == nil {
		t.Fatal("different existing destination origin overwritten")
	}
	if e = preserveEnvironmentOrigin(unmarked, strong); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(strong + ":Zone.Identifier")
	if e != nil || !bytes.Equal(b, strongMark) {
		t.Fatal("unmarked source weakened destination protection")
	}
}

func TestWindowsEnvironmentOwnedRootAndNewChildrenHavePrivateACL(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	outside := filepath.Join(testDirectory(t), "unrelated")
	if e := os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	values := map[string]string{"HONGAI_FIXTURE_ROOT": root, "HONGAI_FIXTURE_OUTSIDE": outside}
	before, e := windowsEnvironmentCommand(ctx, `(Get-Acl -LiteralPath $env:HONGAI_FIXTURE_OUTSIDE).Sddl`, values).Output()
	if e != nil {
		t.Fatal("outside ACL fixture unavailable")
	}
	setup := `$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false);foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')),(New-Object Security.Principal.SecurityIdentifier('S-1-5-11')))){$r=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($r)};(Get-Item -LiteralPath $env:HONGAI_FIXTURE_ROOT -Force).SetAccessControl($acl)`
	if e = windowsEnvironmentCommand(ctx, setup, values).Run(); e != nil {
		t.Fatal("broad inherited-ACL fixture could not be prepared")
	}
	for n := 0; n < 3; n++ {
		if e = secureEnvironmentDataRoot(root); e != nil {
			t.Fatal(e)
		}
	}
	child := filepath.Join(root, "private-child.json")
	if e = atomicReplace(child, []byte("synthetic-data")); e != nil {
		t.Fatal(e)
	}
	values["HONGAI_FIXTURE_CHILD"] = child
	check := `$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;foreach($p in @($env:HONGAI_FIXTURE_ROOT,$env:HONGAI_FIXTURE_CHILD,(Join-Path $env:HONGAI_FIXTURE_ROOT 'environment-owner.json'))){$a=Get-Acl -LiteralPath $p;$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($rules.Count -ne 2){exit 2};foreach($r in $rules){if($r.IdentityReference.Value -cnotin @($sid,'S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl'){exit 3}}};if(-not (Get-Acl -LiteralPath $env:HONGAI_FIXTURE_ROOT).AreAccessRulesProtected){exit 4}`
	if e = windowsEnvironmentCommand(ctx, check, values).Run(); e != nil {
		t.Fatal("component root or newly created child retained nonprivate permissions")
	}
	after, e := windowsEnvironmentCommand(ctx, `(Get-Acl -LiteralPath $env:HONGAI_FIXTURE_OUTSIDE).Sddl`, values).Output()
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("unrelated directory ACL changed")
	}
	unowned := testDirectory(t)
	values["HONGAI_FIXTURE_OUTSIDE"] = unowned
	before, e = windowsEnvironmentCommand(ctx, `(Get-Acl -LiteralPath $env:HONGAI_FIXTURE_OUTSIDE).Sddl`, values).Output()
	if e != nil {
		t.Fatal(e)
	}
	if secureEnvironmentDataRoot(unowned) == nil {
		t.Fatal("unowned directory accepted")
	}
	after, e = windowsEnvironmentCommand(ctx, `(Get-Acl -LiteralPath $env:HONGAI_FIXTURE_OUTSIDE).Sddl`, values).Output()
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected directory ACL changed")
	}
}

func TestWindowsEnvironmentDefaultUsesCustomerApplicationData(t *testing.T) {
	p := testDirectory(t)
	t.Setenv("LOCALAPPDATA", p)
	got, e := defaultEnvironmentRoot()
	if e != nil || got != filepath.Join(p, "HONGAI-Environment") {
		t.Fatal("trusted per-user default changed")
	}
}
