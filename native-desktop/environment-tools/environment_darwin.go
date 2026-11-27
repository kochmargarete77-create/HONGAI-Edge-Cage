//go:build darwin

package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func discoverOfficialClient(ctx context.Context) (OfficialClient, string, error) {
	tz := "UNKNOWN"
	if p, e := filepath.EvalSymlinks("/etc/localtime"); e == nil {
		tz = macSystemTimeZonePath(p)
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return OfficialClient{}, tz, errors.New("CUSTOMER_HOME_UNAVAILABLE")
	}
	client := OfficialClient{Kind: "OFFICIAL_APP_BUNDLE_OR_NOT_INSTALLED", ProfilePath: filepath.Join(home, "Library", "Application Support", "Claude"), ProfileSelection: "STANDARD_PROFILE_CANDIDATE_NOT_PROVEN_ACTIVE"}
	if s, e := os.Stat(client.ProfilePath); e == nil && s.IsDir() {
		client.ProfileExists = true
	}
	for _, p := range []string{"/Applications/Claude.app", filepath.Join(home, "Applications", "Claude.app")} {
		if s, e := os.Stat(p); e != nil || !s.IsDir() {
			continue
		}
		client.Installed = true
		client.Path = p
		if e := verifyMacEnvironmentClient(ctx, p); e != nil {
			continue
		}
		client.Verified = true
		plist := filepath.Join(p, "Contents", "Info.plist")
		v, e := exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-", plist).Output()
		if e != nil {
			v, e = exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", "CFBundleVersion", "raw", "-o", "-", plist).Output()
		}
		if e != nil {
			return client, tz, errors.New("OFFICIAL_APP_VERSION_UNREADABLE")
		}
		client.Version = strings.TrimSpace(string(v))
		client.ApplicationID = "com.anthropic.claudefordesktop"
		client.Architecture = "UNKNOWN"
		executable, e := exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", "CFBundleExecutable", "raw", "-o", "-", plist).Output()
		name := strings.TrimSpace(string(executable))
		if e != nil || !validMacBundleExecutableName(name) {
			return client, tz, errors.New("OFFICIAL_APP_EXECUTABLE_METADATA_INVALID")
		}
		image := filepath.Join(p, "Contents", "MacOS", name)
		if fat, e := macho.OpenFat(image); e == nil {
			var arch []string
			for _, a := range fat.Arches {
				arch = append(arch, a.Cpu.String())
			}
			client.Architecture = strings.Join(arch, " ")
			fat.Close()
		} else if thin, e := macho.Open(image); e == nil {
			client.Architecture = thin.Cpu.String()
			thin.Close()
		}
		return client, tz, nil
	}
	return client, tz, nil
}
func launchOfficialClient(ctx context.Context, c OfficialClient) error {
	if !c.Installed || !c.Verified || c.ApplicationID != "com.anthropic.claudefordesktop" {
		return errors.New("VERIFIED_OFFICIAL_APP_REQUIRED")
	}
	if !filepath.IsAbs(c.Path) {
		return errors.New("OFFICIAL_APP_ABSOLUTE_PATH_REQUIRED")
	}
	if e := verifyMacEnvironmentClient(ctx, c.Path); e != nil {
		return e
	}
	if e := exec.CommandContext(ctx, "/usr/bin/open", "-a", c.Path).Run(); e != nil {
		return errors.New("OFFICIAL_APP_ACTIVATION_FAILED")
	}
	return nil
}
func openEnvironmentBrowser(address string) error {
	if !validEnvironmentBrowserAddress(address) {
		return errors.New("LOCAL_WORKBENCH_BROWSER_ADDRESS_INVALID")
	}
	if e := exec.Command("/usr/bin/open", address).Run(); e != nil {
		return errors.New("OPEN_LOCAL_WORKBENCH_FAILED")
	}
	return nil
}

func validEnvironmentBrowserAddress(address string) bool {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	port, e := strconv.Atoi(u.Port())
	return e == nil && port > 0 && port <= 65535 && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(u.Fragment)
}

func macSystemTimeZonePath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i, part := range parts {
		if part == "zoneinfo" || strings.HasPrefix(part, "zoneinfo.") {
			rest := parts[i+1:]
			if len(rest) > 0 && (rest[0] == "posix" || rest[0] == "right") {
				rest = rest[1:]
			}
			if len(rest) > 0 {
				return strings.Join(rest, "/")
			}
		}
	}
	return "UNKNOWN"
}
func validMacBundleExecutableName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func verifyMacEnvironmentClient(parent context.Context, p string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	const requirement = `anchor apple generic and identifier "com.anthropic.claudefordesktop" and certificate leaf[subject.OU] = "Q6L2SF6YDW"`
	if e := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "-R="+requirement, p).Run(); e != nil {
		return errors.New("OFFICIAL_APP_SIGNATURE_OR_IDENTITY_NOT_VERIFIED")
	}
	return nil
}

type originOutput struct{ bytes.Buffer }

func (b *originOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 262144 {
		return 0, errors.New("ORIGIN_METADATA_OUTPUT_TOO_LARGE")
	}
	return b.Buffer.Write(p)
}
func macOriginCommand(ctx context.Context, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, "/usr/bin/xattr", args...)
	var out originOutput
	c.Stdout = &out
	c.Stderr = io.Discard
	if e := c.Run(); e != nil {
		return nil, errors.New("ORIGIN_METADATA_COMMAND_FAILED")
	}
	return out.Bytes(), nil
}
func readMacQuarantine(ctx context.Context, p string) ([]byte, bool, error) {
	list, e := macOriginCommand(ctx, p)
	if e != nil {
		return nil, false, e
	}
	present := false
	for _, name := range strings.Split(string(list), "\n") {
		if strings.TrimSpace(name) == "com.apple.quarantine" {
			present = true
			break
		}
	}
	if !present {
		return nil, false, nil
	}
	out, e := macOriginCommand(ctx, "-px", "com.apple.quarantine", p)
	if e != nil {
		return nil, false, e
	}
	compact := strings.Join(strings.Fields(string(out)), "")
	if len(compact) > 131072 {
		return nil, false, errors.New("ORIGIN_METADATA_OUTSIDE_LIMIT")
	}
	b, e := hex.DecodeString(compact)
	if e != nil {
		return nil, false, errors.New("ORIGIN_METADATA_ENCODING_INVALID")
	}
	return b, true, nil
}

// Preserve the source quarantine attribute without clearing Gatekeeper state or
// replacing stronger, different provenance already present at the destination.
func preserveEnvironmentOrigin(source, target string) error {
	for _, p := range []string{source, target} {
		if !filepath.IsAbs(p) {
			return errors.New("ORIGIN_METADATA_REQUIRES_ABSOLUTE_PATHS")
		}
		info, e := os.Lstat(p)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("ORIGIN_METADATA_REQUIRES_REGULAR_RUNTIME_FILES")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, present, e := readMacQuarantine(ctx, source)
	if e != nil {
		return errors.New("SOURCE_ORIGIN_METADATA_UNREADABLE")
	}
	if !present {
		return nil
	}
	old, present, e := readMacQuarantine(ctx, target)
	if e != nil {
		return errors.New("DESTINATION_ORIGIN_METADATA_UNREADABLE")
	}
	if present {
		if bytes.Equal(old, b) {
			return nil
		}
		return errors.New("DESTINATION_ORIGIN_METADATA_DIFFERS_REVIEW_REQUIRED")
	}
	if _, e = macOriginCommand(ctx, "-wx", "com.apple.quarantine", hex.EncodeToString(b), target); e != nil {
		return errors.New("DESTINATION_ORIGIN_METADATA_COPY_FAILED")
	}
	check, present, e := readMacQuarantine(ctx, target)
	if e != nil || !present || !bytes.Equal(check, b) {
		return errors.New("DESTINATION_ORIGIN_METADATA_VERIFY_FAILED")
	}
	return nil
}

// The file is persistent: unlinking a flock guard would permit two different
// inodes to protect the same lease transition. Only the descriptor is released.
func environmentTransitionGuard(root string) (func(), error) {
	canonical, e := realPath(root, true)
	if e != nil {
		return nil, e
	}
	p := filepath.Join(canonical, ".environment-operations.guard")
	if info, e := os.Lstat(p); e == nil && !info.Mode().IsRegular() {
		return nil, errors.New("ENVIRONMENT_GUARD_PATH_INVALID")
	} else if e != nil && !os.IsNotExist(e) {
		return nil, errors.New("ENVIRONMENT_GUARD_PATH_UNREADABLE")
	}
	f, e := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, errors.New("ENVIRONMENT_GUARD_OPEN_FAILED")
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("ENVIRONMENT_GUARD_FILE_INVALID")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("ENVIRONMENT_GUARD_OWNER_OR_LINK_INVALID")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN && e != syscall.EINTR {
			f.Close()
			return nil, errors.New("ENVIRONMENT_GUARD_LOCK_FAILED")
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, errors.New("ENVIRONMENT_GUARD_TIMEOUT")
		}
		time.Sleep(15 * time.Millisecond)
	}
	current, e := os.Lstat(p)
	if e != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, errors.New("ENVIRONMENT_GUARD_REPLACED_DURING_ACQUIRE")
	}
	var once sync.Once
	return func() { once.Do(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }) }, nil
}

// macOS mode bits do not remove an inherited extended ACL. Remove only this
// component root's ACL, then verify its private mode; never recurse.
func secureEnvironmentDataRoot(root string) error {
	canonical, e := realPath(root, true)
	if e != nil {
		return e
	}
	var owner environmentOwner
	if decodeFile(filepath.Join(canonical, "environment-owner.json"), &owner) != nil || owner.Schema != "hongai.environment-owner.v1" || !samePath(owner.Root, canonical) || owner.UserID != strconv.Itoa(os.Geteuid()) {
		return errors.New("ENVIRONMENT_ROOT_OWNERSHIP_REQUIRED")
	}
	info, e := os.Lstat(canonical)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ENVIRONMENT_ROOT_DIRECTORY_INVALID")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("ENVIRONMENT_ROOT_OWNER_MISMATCH")
	}
	ownerFile := filepath.Join(canonical, "environment-owner.json")
	ownerInfo, e := os.Lstat(ownerFile)
	if e != nil || !ownerInfo.Mode().IsRegular() {
		return errors.New("ENVIRONMENT_OWNER_FILE_TYPE_INVALID")
	}
	ownerStat, ok := ownerInfo.Sys().(*syscall.Stat_t)
	if !ok || ownerStat.Uid != uint32(os.Geteuid()) || ownerStat.Nlink != 1 {
		return errors.New("ENVIRONMENT_OWNER_FILE_OWNERSHIP_INVALID")
	}
	if e = os.Chmod(canonical, 0700); e != nil {
		return errors.New("ENVIRONMENT_ROOT_PRIVATE_MODE_FAILED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e = exec.CommandContext(ctx, "/bin/chmod", "-N", canonical).Run(); e != nil {
		return errors.New("ENVIRONMENT_ROOT_INHERITED_ACL_REMOVE_FAILED")
	}
	// This one known metadata file predates root hardening. Its inherited ACL
	// must be removed separately on macOS; no application or project tree is walked.
	if e = exec.CommandContext(ctx, "/bin/chmod", "-N", ownerFile).Run(); e != nil {
		return errors.New("ENVIRONMENT_OWNER_FILE_ACL_REMOVE_FAILED")
	}
	if e = os.Chmod(ownerFile, 0600); e != nil {
		return errors.New("ENVIRONMENT_OWNER_FILE_PRIVATE_MODE_FAILED")
	}
	after, e := os.Lstat(canonical)
	if e != nil || !os.SameFile(info, after) || after.Mode().Perm() != 0700 {
		return errors.New("ENVIRONMENT_ROOT_PRIVATE_MODE_NOT_VERIFIED")
	}
	check, e := exec.CommandContext(ctx, "/bin/ls", "-lde", canonical).Output()
	if e != nil {
		return errors.New("ENVIRONMENT_ROOT_ACL_STATUS_UNREADABLE")
	}
	fields := strings.Fields(string(check))
	if len(fields) == 0 || strings.Contains(fields[0], "+") {
		return errors.New("ENVIRONMENT_ROOT_ACL_STILL_PRESENT")
	}
	ownerAfter, e := os.Lstat(ownerFile)
	if e != nil || !os.SameFile(ownerInfo, ownerAfter) || ownerAfter.Mode().Perm() != 0600 {
		return errors.New("ENVIRONMENT_OWNER_FILE_PRIVATE_MODE_NOT_VERIFIED")
	}
	return nil
}
func defaultEnvironmentRoot() (string, error) {
	p, e := os.UserHomeDir()
	if e != nil {
		return "", errors.New("CUSTOMER_HOME_UNAVAILABLE")
	}
	parent := filepath.Join(p, "Library", "Application Support")
	if _, e = os.Stat(parent); e != nil {
		return "", errors.New("CUSTOMER_APPLICATION_SUPPORT_UNAVAILABLE")
	}
	return filepath.Join(parent, "HONGAI-Environment"), nil
}
func shellQuote(p string) string { return "'" + strings.ReplaceAll(p, "'", "'\"'\"'") + "'" }
func writeEnvironmentLauncher(root, target string) error {
	content := "#!/bin/sh\nset -eu\nexec " + shellQuote(target) + " environment use --root " + shellQuote(root) + "\n"
	p := filepath.Join(root, "HONGAI-Environment.command")
	if e := atomicReplace(p, []byte(content)); e != nil {
		return e
	}
	if e := os.Chmod(p, 0700); e != nil {
		return errors.New("MAC_LAUNCHER_PERMISSION_FAILED")
	}
	return nil
}
func environmentProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	e := syscall.Kill(pid, 0)
	return e == nil || e == syscall.EPERM
}
