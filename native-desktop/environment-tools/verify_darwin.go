//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func verifyOfficialInstaller(p string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if strings.ToLower(filepath.Ext(p)) == ".app" {
		requirement := `anchor apple generic and identifier "com.anthropic.claudefordesktop" and certificate leaf[subject.OU] = "Q6L2SF6YDW"`
		if e := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "-R="+requirement, p).Run(); e != nil {
			return errors.New("OFFICIAL_APP_SIGNATURE_OR_IDENTITY_NOT_VERIFIED")
		}
		return nil
	}
	if strings.ToLower(filepath.Ext(p)) != ".pkg" {
		return errors.New("MAC_SIGNED_PKG_INTAKE_REQUIRED_DMG_FLOW_NOT_ACCEPTED")
	}
	out, e := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--check-signature", p).Output()
	if e != nil {
		return errors.New("OFFICIAL_INSTALLER_SIGNATURE_NOT_VERIFIED")
	}
	text := string(out)
	if !regexp.MustCompile(`Developer ID Installer: Anthropic(?:,? PBC)? \(Q6L2SF6YDW\)`).MatchString(text) {
		return errors.New("ANTHROPIC_INSTALLER_PUBLISHER_NOT_VERIFIED")
	}
	if !strings.Contains(text, "signed by a certificate trusted by") {
		return errors.New("INSTALLER_TRUST_NOT_VERIFIED")
	}
	return nil
}
