package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

const environmentSupportExportLimit = 20
const environmentSupportExportBytes = 64 << 10

var environmentSupportExportName = regexp.MustCompile(`^hongai-support-[a-f0-9]{32}\.json$`)

// validateEnvironmentDiagnosticsDirectory is read-only. In particular, a reveal
// request must not turn a missing directory or a user-selected path into state.
func validateEnvironmentDiagnosticsDirectory(root string) (string, error) {
	ownedRoot, e := environmentRoot(root, false)
	if e != nil || !validEnvironmentOwner(ownedRoot) {
		return "", errors.New("SUPPORT_EXPORT_OWNED_ENVIRONMENT_REQUIRED")
	}
	p, e := realPath(filepath.Join(ownedRoot, "diagnostics"), true)
	if e != nil || !samePath(filepath.Dir(p), ownedRoot) {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_REQUIRES_REVIEW")
	}
	i, e := os.Lstat(p)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && i.Mode().Perm() != 0700) {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_NOT_PRIVATE")
	}
	return p, nil
}

// saveEnvironmentSupportExport receives the already redacted support report.
// It is not a generic file-write endpoint and never serializes account state,
// settings or other local data itself. Old and unknown files are never removed.
func saveEnvironmentSupportExport(root string, report map[string]any) (string, error) {
	if report["schema"] != "hongai.environment-support.v1" {
		return "", errors.New("SUPPORT_EXPORT_SCHEMA_REQUIRED")
	}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil || len(b) >= environmentSupportExportBytes {
		return "", errors.New("SUPPORT_EXPORT_PAYLOAD_OUTSIDE_LIMIT")
	}
	root, e = environmentRoot(root, false)
	if e != nil || !validEnvironmentOwner(root) {
		return "", errors.New("SUPPORT_EXPORT_OWNED_ENVIRONMENT_REQUIRED")
	}
	// Reuse the short OS guard to serialize the count/create transition across
	// manager processes. This does not take or remove an active workbench lease.
	release, e := environmentTransitionGuard(root)
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_GUARD_UNAVAILABLE")
	}
	defer release()
	if !validEnvironmentOwner(root) {
		return "", errors.New("SUPPORT_EXPORT_OWNERSHIP_CHANGED")
	}
	dir := filepath.Join(root, "diagnostics")
	if _, e = os.Lstat(dir); os.IsNotExist(e) {
		// Keep even a newly created directory on later failure: no broad cleanup
		// may remove files another actor put there in the meantime.
		if e = os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
			return "", errors.New("SUPPORT_EXPORT_DIRECTORY_CREATE_FAILED")
		}
	} else if e != nil {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_UNREADABLE")
	}
	dir, e = validateEnvironmentDiagnosticsDirectory(root)
	if e != nil {
		return "", e
	}
	directoryInfo, e := os.Lstat(dir)
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_CHANGED")
	}
	// A bound directory handle keeps creation and failure cleanup inside this
	// exact directory even if a same-user process renames a path concurrently.
	bound, e := os.OpenRoot(dir)
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_OPEN_FAILED")
	}
	defer bound.Close()
	current, e := bound.Lstat(".")
	if e != nil || !os.SameFile(directoryInfo, current) {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_CHANGED")
	}
	listing, e := bound.Open(".")
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_READ_FAILED")
	}
	count := 0
	for {
		entries, readError := listing.ReadDir(64)
		for _, entry := range entries {
			if !environmentSupportExportName.MatchString(entry.Name()) {
				continue
			}
			info, statError := bound.Lstat(entry.Name())
			if statError != nil || !info.Mode().IsRegular() {
				listing.Close()
				return "", errors.New("SUPPORT_EXPORT_ENTRY_REQUIRES_REVIEW")
			}
			count++
			if count >= environmentSupportExportLimit {
				listing.Close()
				return "", errors.New("SUPPORT_EXPORT_LIMIT_REACHED_KEEP_EXISTING_REPORTS")
			}
		}
		if readError == io.EOF {
			break
		}
		if readError != nil {
			listing.Close()
			return "", errors.New("SUPPORT_EXPORT_DIRECTORY_READ_FAILED")
		}
	}
	if e = listing.Close(); e != nil {
		return "", errors.New("SUPPORT_EXPORT_DIRECTORY_READ_FAILED")
	}
	name := "hongai-support-" + randomName() + ".json"
	f, e := bound.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_CREATE_FAILED")
	}
	created, statError := f.Stat()
	saved := false
	defer func() {
		if !saved && statError == nil {
			if now, checkError := bound.Lstat(name); checkError == nil && now.Mode().IsRegular() && os.SameFile(created, now) {
				_ = bound.Remove(name)
			}
		}
	}()
	n, writeError := f.Write(b)
	if writeError == nil && n != len(b) {
		writeError = io.ErrShortWrite
	}
	if writeError == nil {
		writeError = f.Sync()
	}
	closeError := f.Close()
	if statError != nil || writeError != nil || closeError != nil {
		return "", errors.New("SUPPORT_EXPORT_WRITE_FAILED")
	}
	check, e := bound.Open(name)
	if e != nil {
		return "", errors.New("SUPPORT_EXPORT_READBACK_FAILED")
	}
	checkInfo, checkError := check.Stat()
	readBack, readError := io.ReadAll(io.LimitReader(check, environmentSupportExportBytes))
	closeError = check.Close()
	if checkError != nil || !checkInfo.Mode().IsRegular() || !os.SameFile(created, checkInfo) || readError != nil || closeError != nil || digest(readBack) != digest(b) {
		return "", errors.New("SUPPORT_EXPORT_READBACK_FAILED")
	}
	verifiedDir, e := validateEnvironmentDiagnosticsDirectory(root)
	verifiedDirectoryInfo, directoryStatError := os.Lstat(dir)
	now, finalStatError := os.Lstat(filepath.Join(dir, name))
	if e != nil || !samePath(verifiedDir, dir) || directoryStatError != nil || !os.SameFile(directoryInfo, verifiedDirectoryInfo) || finalStatError != nil || !now.Mode().IsRegular() || !os.SameFile(created, now) {
		return "", errors.New("SUPPORT_EXPORT_PATH_CHANGED")
	}
	saved = true
	return filepath.Join(dir, name), nil
}
