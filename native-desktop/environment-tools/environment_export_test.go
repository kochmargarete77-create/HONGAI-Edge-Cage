package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func environmentExportFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(testDirectory(t), "environment")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := saveEnvironmentOwner(root); e != nil {
		t.Fatal(e)
	}
	return root
}

func TestEnvironmentNativeSupportExportContentAndBoundedRetention(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	report := map[string]any{"schema": "hongai.environment-support.v1", "scope": "SYNTHETIC_REDACTED_TEST", "containsCredentials": false}
	if _, e := validateEnvironmentDiagnosticsDirectory(root); e == nil {
		t.Fatal("read-only validation created or accepted a missing diagnostics directory")
	}
	if _, e := os.Lstat(filepath.Join(root, "diagnostics")); !os.IsNotExist(e) {
		t.Fatal("read-only validation created state")
	}
	p, e := saveEnvironmentSupportExport(root, report)
	if e != nil {
		t.Fatal(e)
	}
	dir, e := validateEnvironmentDiagnosticsDirectory(root)
	if e != nil || filepath.Dir(p) != dir || !environmentSupportExportName.MatchString(filepath.Base(p)) {
		t.Fatal("export escaped fixed diagnostics directory or naming policy")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var decoded map[string]any
	if json.Unmarshal(b, &decoded) != nil || decoded["schema"] != report["schema"] || decoded["scope"] != report["scope"] || decoded["containsCredentials"] != false {
		t.Fatal("saved report differs from input")
	}
	fileInfo, _ := os.Stat(p)
	dirInfo, _ := os.Stat(dir)
	if runtime.GOOS != "windows" && (fileInfo.Mode().Perm() != 0600 || dirInfo.Mode().Perm() != 0700) {
		t.Fatal("export or diagnostics directory permissions are not private")
	}
	unknown := filepath.Join(dir, "customer-notes.txt")
	if e = os.WriteFile(unknown, []byte("CUSTOMER_FILE_MUST_SURVIVE"), 0600); e != nil {
		t.Fatal(e)
	}
	// Concurrent saves must share the same count/create guard, not exceed 20.
	var wg sync.WaitGroup
	errors := make(chan error, environmentSupportExportLimit+2)
	for i := 0; i < environmentSupportExportLimit+2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := saveEnvironmentSupportExport(root, report); errors <- e }()
	}
	wg.Wait()
	close(errors)
	successes, limited := 1, 0
	for e := range errors {
		if e == nil {
			successes++
		} else if e.Error() == "SUPPORT_EXPORT_LIMIT_REACHED_KEEP_EXISTING_REPORTS" {
			limited++
		} else {
			t.Fatal(e)
		}
	}
	if successes != environmentSupportExportLimit || limited != 3 {
		t.Fatalf("export quota was not enforced: saved=%d limited=%d", successes, limited)
	}
	if after, e := os.ReadFile(p); e != nil || digest(after) != digest(b) {
		t.Fatal("an existing report was overwritten or removed")
	}
	if after, e := os.ReadFile(unknown); e != nil || string(after) != "CUSTOMER_FILE_MUST_SURVIVE" {
		t.Fatal("unknown customer file was changed or removed")
	}
	if _, e := removeEnvironment(root); e == nil {
		t.Fatal("recoverable uninstall accepted unknown customer diagnostics file")
	}
	if after, e := os.ReadFile(unknown); e != nil || string(after) != "CUSTOMER_FILE_MUST_SURVIVE" {
		t.Fatal("rejected uninstall changed unknown customer diagnostics")
	}
}

func TestEnvironmentNativeSupportExportRejectsUnownedUnsafeAndOversizedState(t *testing.T) {
	report := map[string]any{"schema": "hongai.environment-support.v1"}
	t.Run("recoverable-uninstall-preserves-valid-reports", func(t *testing.T) {
		root, _ := fixtureEnvironment(t)
		p, e := saveEnvironmentSupportExport(root, report)
		if e != nil {
			t.Fatal(e)
		}
		before, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		result, e := removeEnvironment(root)
		if e != nil || result["status"] != "RECOVERABLY_REMOVED" {
			t.Fatalf("owned reports blocked recoverable uninstall: %v", e)
		}
		recovery, ok := result["recoveryDirectory"].(string)
		if !ok || !samePath(filepath.Dir(recovery), filepath.Dir(root)) {
			t.Fatal("recoverable uninstall moved outside the approved parent")
		}
		retained := filepath.Join(recovery, "diagnostics", filepath.Base(p))
		if after, e := os.ReadFile(retained); e != nil || digest(before) != digest(after) {
			t.Fatal("recoverable uninstall lost or altered the exported report")
		}
	})
	t.Run("ownership-and-schema", func(t *testing.T) {
		root := environmentExportFixture(t)
		if _, e := saveEnvironmentSupportExport(root, map[string]any{"schema": "not-a-support-report"}); e == nil {
			t.Fatal("unexpected schema accepted")
		}
		if _, e := saveEnvironmentSupportExport(root, map[string]any{"schema": "hongai.environment-support.v1", "data": strings.Repeat("x", environmentSupportExportBytes)}); e == nil {
			t.Fatal("oversized export accepted")
		}
		if e := os.Remove(filepath.Join(root, "environment-owner.json")); e != nil {
			t.Fatal(e)
		}
		if _, e := saveEnvironmentSupportExport(root, report); e == nil {
			t.Fatal("unowned environment accepted")
		}
		if _, e := os.Lstat(filepath.Join(root, "diagnostics")); !os.IsNotExist(e) {
			t.Fatal("invalid request created diagnostics directory")
		}
	})
	t.Run("customer-file-instead-of-directory", func(t *testing.T) {
		root := environmentExportFixture(t)
		p := filepath.Join(root, "diagnostics")
		if e := os.WriteFile(p, []byte("DO_NOT_OVERWRITE"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := saveEnvironmentSupportExport(root, report); e == nil {
			t.Fatal("a customer file was accepted as directory")
		}
		if b, e := os.ReadFile(p); e != nil || string(b) != "DO_NOT_OVERWRITE" {
			t.Fatal("customer file overwritten or removed")
		}
	})
	t.Run("linked-directory", func(t *testing.T) {
		root := environmentExportFixture(t)
		target := filepath.Join(testDirectory(t), "outside")
		if e := os.Mkdir(target, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink(target, filepath.Join(root, "diagnostics")); e != nil {
			t.Skip("host does not grant directory symlink creation")
		}
		if _, e := validateEnvironmentDiagnosticsDirectory(root); e == nil {
			t.Fatal("linked diagnostics reveal accepted")
		}
		if _, e := saveEnvironmentSupportExport(root, report); e == nil {
			t.Fatal("linked diagnostics export accepted")
		}
		if entries, e := os.ReadDir(target); e != nil || len(entries) != 0 {
			t.Fatal("export wrote outside the owned root")
		}
	})
	t.Run("controlled-name-is-customer-directory", func(t *testing.T) {
		root := environmentExportFixture(t)
		dir := filepath.Join(root, "diagnostics")
		p := filepath.Join(dir, "hongai-support-"+strings.Repeat("a", 32)+".json")
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
		marker := filepath.Join(p, "customer.txt")
		if e := os.WriteFile(marker, []byte("DO_NOT_CLEAN"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := saveEnvironmentSupportExport(root, report); e == nil {
			t.Fatal("non-regular controlled report name accepted")
		}
		if b, e := os.ReadFile(marker); e != nil || string(b) != "DO_NOT_CLEAN" {
			t.Fatal("unknown directory contents changed")
		}
	})
}
