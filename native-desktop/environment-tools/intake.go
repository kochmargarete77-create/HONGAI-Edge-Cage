package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func inspectInstaller(file, source string) (map[string]any, error) {
	p, e := realPath(file, false)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(source)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return nil, errors.New("DECLARED_OFFICIAL_HTTPS_SOURCE_REQUIRED")
	}
	host := strings.ToLower(u.Hostname())
	if host != "claude.ai" && host != "claude.com" && host != "downloads.claude.ai" {
		return nil, errors.New("DECLARED_SOURCE_HOST_NOT_APPROVED")
	}
	ext := strings.ToLower(filepath.Ext(p))
	if ext != ".exe" && ext != ".msix" && ext != ".pkg" {
		return nil, errors.New("SIGNED_NATIVE_EXE_MSIX_OR_PKG_REQUIRED")
	}
	before, e := os.Stat(p)
	if e != nil || before.Size() < 4096 || before.Size() > 2_000_000_000 {
		return nil, errors.New("INSTALLER_SIZE_OUTSIDE_LIMIT")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, errors.New("INSTALLER_UNREADABLE")
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil {
		return nil, errors.New("INSTALLER_HASH_FAILED")
	}
	if e = verifyOfficialInstaller(p); e != nil {
		return nil, e
	}
	after, e := os.Stat(p)
	if e != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("INSTALLER_CHANGED_DURING_VERIFICATION")
	}
	return map[string]any{"schema": "hongai.official-installer-intake.v1", "phase": "SIGNED_PUBLISHER_VERIFIED_INSTALL_ROLE_PENDING", "sha256": hex.EncodeToString(h.Sum(nil)), "bytes": before.Size(), "declaredSourceHost": host, "sourceIsOperatorDeclaredNotBrowserHistoryProof": true, "verifiedAt": time.Now().UTC().Format(time.RFC3339), "signaturePublisher": "Anthropic", "installerStarted": false, "installationCompleted": false, "initialLaunchProtected": false, "installerBytesModified": false, "bundledClaudeRuntime": false, "preAuthenticatedStateIncluded": false, "allEnvironmentAdaptersAccepted": false}, nil
}
