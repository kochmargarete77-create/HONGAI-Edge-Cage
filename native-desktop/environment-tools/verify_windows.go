//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func verifyOfficialInstaller(p string) error {
	ext := strings.ToLower(filepath.Ext(p))
	if ext != ".exe" && ext != ".msix" {
		return errors.New("WINDOWS_NATIVE_INSTALLER_REQUIRED")
	}
	// The path is data in an environment variable, never interpolated as code.
	script := `$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath $env:HONGAI_VERIFY_FILE;if($s.Status -ne 'Valid' -or -not $s.SignerCertificate){exit 2};$name=$s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);if($name -cnotin @('Anthropic, PBC','Anthropic PBC')){exit 3};exit 0`
	powershell := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	c := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-Command", script)
	c.Env = append(os.Environ(), "HONGAI_VERIFY_FILE="+p)
	if e := c.Run(); e != nil {
		return errors.New("OFFICIAL_ANTHROPIC_SIGNATURE_NOT_VERIFIED")
	}
	return nil
}
