package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScopedPrivacyAuditExportsCountsWithoutSelectedValuesOrPaths(t *testing.T) {
	const selectedPath = "/result/structuredContent/privateDiagnostic"
	filter, err := newFilter(Policy{Version: 2, Rules: []Rule{{ID: "private_test", Value: canary, Paths: []string{selectedPath}}}})
	if err != nil {
		t.Fatal(err)
	}
	var stats Counts
	message, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"structuredContent": map[string]any{"privateDiagnostic": canary}}})
	if _, err = filter.message(message, &stats); err != nil {
		t.Fatal(err)
	}
	root := testDirectory(t)
	if err = writeAudit(root, stats, "SUCCESS"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "audit-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("AUDIT_NOT_WRITTEN")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{canary, selectedPath, "privateDiagnostic", "private_test"} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("PRIVATE_POLICY_DATA_ENTERED_AUDIT")
		}
	}
	var report map[string]any
	if json.Unmarshal(data, &report) != nil {
		t.Fatal("AUDIT_INVALID_JSON")
	}
	if report["policyVersion"] != float64(2) || report["configuredPaths"] != float64(1) || report["scopedPathsMatched"] != float64(1) || report["replacements"] != float64(1) {
		t.Fatal("SCOPED_COVERAGE_NOT_EXPORTED")
	}
	if report["rawPayloadsExported"] != false || report["nativeHardwareReadsCovered"] != false {
		t.Fatal("AUDIT_COVERAGE_OVERSTATED")
	}
}
