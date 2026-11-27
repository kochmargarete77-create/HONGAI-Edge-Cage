//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

func windowsEnvironmentCommand(ctx context.Context, script string, values map[string]string) *exec.Cmd {
	p := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	c := exec.CommandContext(ctx, p, "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);$OutputEncoding=[Console]::OutputEncoding;$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules');`+script)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	c.Env = mergedEnvironment(os.Environ(), values, true)
	return c
}
func discoverOfficialClient(ctx context.Context) (OfficialClient, string, error) {
	var r struct {
		Installed    bool   `json:"installed"`
		Verified     bool   `json:"verified"`
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
		ID           string `json:"id"`
		Path         string `json:"path"`
		TimeZone     string `json:"timeZone"`
	}
	script := `$p=Get-AppxPackage -Name Claude|Where-Object {$_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc'}|Sort-Object Version -Descending|Select-Object -First 1;$tz=(Get-TimeZone).Id;if(!$p){@{installed=$false;timeZone=$tz}|ConvertTo-Json -Compress;exit 0};$m=Get-AppxPackageManifest -Package $p.PackageFullName;$a=@($m.Package.Applications.Application)|Where-Object {$_.Id -eq 'Claude' -or [IO.Path]::GetFileName([string]$_.Executable) -ieq 'Claude.exe'}|Sort-Object @{Expression={if($_.Id -eq 'Claude'){0}else{1}}}|Select-Object -First 1;if(!$a -or [string]$a.Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'){throw 'Unexpected application identity'};$root=[IO.Path]::GetFullPath($p.InstallLocation).TrimEnd('');$exe=[IO.Path]::GetFullPath((Join-Path $root $a.Executable));if(-not $exe.StartsWith($root+'',[StringComparison]::OrdinalIgnoreCase)){throw 'Application path outside package'};$s=Get-AuthenticodeSignature -LiteralPath $exe;$verified=$false;if($s.Status -eq 'Valid' -and $s.SignerCertificate){$n=$s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);$verified=$n -cin @('Anthropic, PBC','Anthropic PBC')};@{installed=$true;verified=$verified;version=[string]$p.Version;architecture=[string]$p.Architecture;id=$p.PackageFamilyName+'!'+$a.Id;path=$exe;timeZone=$tz}|ConvertTo-Json -Compress`
	out, e := windowsEnvironmentCommand(ctx, script, nil).Output()
	if e != nil {
		return OfficialClient{}, "", errors.New("WINDOWS_OFFICIAL_CLIENT_INVENTORY_FAILED")
	}
	if e = json.Unmarshal(out, &r); e != nil {
		return OfficialClient{}, "", errors.New("WINDOWS_INVENTORY_RESPONSE_INVALID")
	}
	profile, exists, selection := windowsClaudeProfileCandidate(os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA"))
	client := OfficialClient{Installed: r.Installed, Verified: r.Verified, Kind: "REGISTERED_MSIX_OR_NOT_INSTALLED", Version: r.Version, Architecture: r.Architecture, ApplicationID: r.ID, Path: r.Path, ProfilePath: profile, ProfileExists: exists, ProfileSelection: selection}
	mapping := map[string]string{"Pacific Standard Time": "America/Los_Angeles", "Eastern Standard Time": "America/New_York", "Central Standard Time": "America/Chicago", "Mountain Standard Time": "America/Denver", "US Mountain Standard Time": "America/Phoenix", "Alaskan Standard Time": "America/Anchorage", "Hawaiian Standard Time": "Pacific/Honolulu"}
	tz := mapping[r.TimeZone]
	if tz == "" {
		tz = r.TimeZone
	}
	return client, tz, nil
}
func launchOfficialClient(ctx context.Context, c OfficialClient) error {
	if !c.Installed || !c.Verified || !regexp.MustCompile(`^Claude_pzs8sxrjxfjjc![A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(c.ApplicationID) {
		return errors.New("VERIFIED_REGISTERED_OFFICIAL_CLIENT_REQUIRED")
	}
	script := `Start-Process -FilePath (Join-Path $env:WINDIR 'explorer.exe') -ArgumentList ('shell:AppsFolder\'+$env:HONGAI_OFFICIAL_APP_ID)`
	if e := windowsEnvironmentCommand(ctx, script, map[string]string{"HONGAI_OFFICIAL_APP_ID": c.ApplicationID}).Run(); e != nil {
		return errors.New("OFFICIAL_APPMODEL_ACTIVATION_FAILED")
	}
	return nil
}
func openEnvironmentBrowser(address string) error {
	if !validEnvironmentBrowserAddress(address) {
		return errors.New("LOCAL_WORKBENCH_BROWSER_ADDRESS_INVALID")
	}
	c := exec.Command(filepath.Join(os.Getenv("WINDIR"), "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", address)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if e := c.Start(); e != nil {
		return errors.New("OPEN_LOCAL_WORKBENCH_FAILED")
	}
	go c.Wait()
	return nil
}
func defaultEnvironmentRoot() (string, error) {
	for _, drive := range []string{`E:\`, `D:\`} {
		if s, e := os.Stat(drive); e == nil && s.IsDir() && windowsUsableDataDrive(drive) {
			return filepath.Join(drive, "HONGAI-Environment"), nil
		}
	}
	p := os.Getenv("LOCALAPPDATA")
	if p == "" {
		return "", errors.New("CUSTOMER_APPLICATION_DATA_DIRECTORY_UNAVAILABLE")
	}
	return filepath.Join(p, "HONGAI-Environment"), nil
}
func writeEnvironmentLauncher(root, target string) error {
	if strings.ContainsAny(root+target, "\r\n\"") {
		return errors.New("LAUNCHER_PATH_CONTAINS_UNSUPPORTED_CHARACTERS")
	}
	// Disable expansion before reading customer paths. Escaping '%' preserves
	// legitimate path characters without evaluating environment substitutions.
	content := "@echo off\r\nsetlocal DisableDelayedExpansion\r\nchcp 65001 >nul\r\n\"" + strings.ReplaceAll(target, "%", "%%") + "\" environment use --root \"" + strings.ReplaceAll(root, "%", "%%") + "\"\r\nif errorlevel 1 pause\r\n"
	return atomicReplace(filepath.Join(root, "HONGAI-Environment.cmd"), []byte(content))
}

func validEnvironmentBrowserAddress(address string) bool {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	port, e := strconv.Atoi(u.Port())
	return e == nil && port > 0 && port <= 65535 && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(u.Fragment)
}

func windowsClaudeProfileCandidate(local, roaming string) (string, bool, string) {
	type candidate struct{ path, label string }
	var candidates []candidate
	if filepath.IsAbs(local) {
		candidates = append(candidates, candidate{filepath.Join(local, "Claude-Data", "Claude_pzs8sxrjxfjjc"), "CURRENT_EXTERNAL_PROFILE_CANDIDATE_NOT_PROVEN_ACTIVE"}, candidate{filepath.Join(local, "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude"), "MSIX_REDIRECTED_PROFILE_CANDIDATE_NOT_PROVEN_ACTIVE"})
	}
	if filepath.IsAbs(roaming) {
		candidates = append(candidates, candidate{filepath.Join(roaming, "Claude"), "LEGACY_PROFILE_CANDIDATE_NOT_PROVEN_ACTIVE"})
	}
	var selected candidate
	found := false
	substantive := 0
	for _, c := range candidates {
		if s, e := os.Stat(c.path); e == nil && s.IsDir() {
			if !found {
				selected = c
				found = true
			}
			for _, name := range []string{"Local State", "Preferences", "config.json", "ant-did"} {
				if _, e = os.Stat(filepath.Join(c.path, name)); e == nil {
					substantive++
					break
				}
			}
		}
	}
	if !found {
		return "", false, "PROFILE_NOT_DISCOVERED_NO_ACCOUNT_DATA_READ"
	}
	if substantive > 1 {
		selected.label = "MULTIPLE_PROFILE_CANDIDATES_REVIEW_REQUIRED"
	}
	return selected.path, true, selected.label
}

func windowsUsableDataDrive(root string) bool {
	p, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return false
	}
	kind, _, _ := kernel32.NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(p)))
	if kind != 3 {
		return false
	}
	var flags uint32
	ok, _, _ := kernel32.NewProc("GetVolumeInformationW").Call(uintptr(unsafe.Pointer(p)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&flags)), 0, 0)
	if ok == 0 || flags&0x00080000 != 0 {
		return false
	}
	var free uint64
	ok, _, _ = kernel32.NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0)
	return ok != 0 && free >= 256<<20
}

// Keep Mark-of-the-Web when moving our already selected runtime. Never erase
// existing destination provenance or turn a missing/failed read into a bypass.
func preserveEnvironmentOrigin(source, target string) error {
	for _, p := range []string{source, target} {
		info, e := os.Lstat(p)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("ORIGIN_METADATA_REQUIRES_REGULAR_RUNTIME_FILES")
		}
	}
	f, e := os.Open(source + ":Zone.Identifier")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return errors.New("SOURCE_ORIGIN_METADATA_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return errors.New("SOURCE_ORIGIN_METADATA_OUTSIDE_LIMIT")
	}
	p := target + ":Zone.Identifier"
	if existing, e := os.ReadFile(p); e == nil {
		if bytes.Equal(existing, b) {
			return nil
		}
		return errors.New("DESTINATION_ORIGIN_METADATA_DIFFERS_REVIEW_REQUIRED")
	} else if !os.IsNotExist(e) {
		return errors.New("DESTINATION_ORIGIN_METADATA_UNREADABLE")
	}
	out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("DESTINATION_ORIGIN_METADATA_COPY_FAILED")
	}
	_, e = out.Write(b)
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e != nil || closeErr != nil {
		return errors.New("DESTINATION_ORIGIN_METADATA_COPY_FAILED")
	}
	check, e := os.ReadFile(p)
	if e != nil || !bytes.Equal(check, b) {
		return errors.New("DESTINATION_ORIGIN_METADATA_VERIFY_FAILED")
	}
	return nil
}

// The named mutex serializes short on-disk lease transitions across sessions.
// A dedicated OS-thread owner makes the returned release safe even when a
// caller invokes it from a different goroutine; it never owns the file lease.
func environmentTransitionGuard(root string) (func(), error) {
	canonical, e := realPath(root, true)
	if e != nil {
		return nil, e
	}
	token, e := syscall.OpenCurrentProcessToken()
	if e != nil {
		return nil, errors.New("ENVIRONMENT_GUARD_USER_ID_UNAVAILABLE")
	}
	user, e := token.GetTokenUser()
	token.Close()
	if e != nil {
		return nil, errors.New("ENVIRONMENT_GUARD_USER_ID_UNAVAILABLE")
	}
	sid, e := user.User.Sid.String()
	if e != nil {
		return nil, errors.New("ENVIRONMENT_GUARD_USER_ID_UNAVAILABLE")
	}
	name, e := syscall.UTF16PtrFromString(`Global\HONGAI.Environment.Transition.` + digest([]byte(strings.ToLower(filepath.Clean(canonical))+"|"+sid)))
	if e != nil {
		return nil, errors.New("ENVIRONMENT_GUARD_NAME_INVALID")
	}
	type result struct {
		release func()
		err     error
	}
	reply := make(chan result, 1)
	releaseRequest := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		h, _, _ := kernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
		if h == 0 {
			reply <- result{err: errors.New("ENVIRONMENT_GUARD_CREATE_FAILED")}
			return
		}
		defer syscall.CloseHandle(syscall.Handle(h))
		wait, e := syscall.WaitForSingleObject(syscall.Handle(h), 3000)
		if e != nil {
			reply <- result{err: errors.New("ENVIRONMENT_GUARD_WAIT_FAILED")}
			return
		}
		if wait == 0x102 {
			reply <- result{err: errors.New("ENVIRONMENT_GUARD_TIMEOUT")}
			return
		}
		if wait != 0 && wait != 0x80 {
			reply <- result{err: errors.New("ENVIRONMENT_GUARD_WAIT_FAILED")}
			return
		}
		reply <- result{release: func() { once.Do(func() { close(releaseRequest) }); <-done }}
		<-releaseRequest
		_, _, _ = kernel32.NewProc("ReleaseMutex").Call(h)
	}()
	r := <-reply
	return r.release, r.err
}
func environmentProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, e := syscall.OpenProcess(0x00100000, false, uint32(pid))
	if e != nil {
		return e != syscall.Errno(87)
	}
	defer syscall.CloseHandle(h)
	r, e := syscall.WaitForSingleObject(h, 0)
	return e != nil || r != syscall.WAIT_OBJECT_0
}
