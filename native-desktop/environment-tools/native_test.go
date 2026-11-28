package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const hostIP = "198.51.100.44"
const canary = "HONGAI_NATIVE_SECRET_78be13"

func TestMain(m *testing.M) {
	if os.Getenv("HONGAI_UPSTREAM_FIXTURE") == "1" {
		nativeFixture()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func fixturePolicy() Policy {
	return Policy{1, []Rule{{ID: "network", Value: hostIP, Encodings: []string{"url", "base64"}}, {ID: "secret", Value: canary, Encodings: []string{"base64"}}, {ID: "timezone", Value: "Asia/Shanghai", Encodings: []string{"url", "base64"}}}}
}
func testDirectory(t *testing.T) string {
	t.Helper()
	parent := os.Getenv("HONGAI_TEST_ROOT")
	if parent == "" {
		t.Fatal("APPROVED_DATA_DRIVE_TEST_ROOT_REQUIRED")
	}
	p, e := os.MkdirTemp(parent, "hongai-native-")
	if e != nil {
		t.Fatal(e)
	}
	// Fixture files stay on the approved data drive. Keychain entries are
	// exact test-owned accounts and are removed on macOS after the test.
	t.Cleanup(func() {
		if runtime.GOOS == "darwin" {
			for _, owned := range []string{p, filepath.Join(p, "component-data")} {
				exec.Command("/usr/bin/security", "delete-generic-password", "-a", keychainTestAccount(owned), "-s", "com.hongai.environment.mcp-privacy").Run()
			}
		}
	})
	return p
}
func TestLiteralAndProtocolPreservation(t *testing.T) {
	f, e := newFilter(fixturePolicy())
	if e != nil {
		t.Fatal(e)
	}
	input := `{"jsonrpc":"2.0","id":9007199254740993123456,"result":{"isError":false,"content":[{"type":"text","text":"patch applied; host 198.51.100.44; business 203.0.113.9; secret HONGAI_NATIVE_SECRET_78be13"}],"structuredContent":{"id":"198.51.100.44","timezone":"Asia/Shanghai","code":"const answer = 42;"}}}`
	var stats Counts
	out, e := f.message([]byte(input), &stats)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{hostIP, canary, "Asia/Shanghai"} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal("CANARY_LEAK")
		}
	}
	for _, s := range []string{"9007199254740993123456", "203.0.113.9", "const answer = 42;", "patch applied", "\"isError\":false"} {
		if !bytes.Contains(out, []byte(s)) {
			t.Fatalf("BUSINESS_OR_PROTOCOL_VALUE_LOST: %s", s)
		}
	}
	if stats.Replacements != 4 {
		t.Fatalf("replacements %d", stats.Replacements)
	}
}
func TestEscapedAndDeclaredEncodedLiterals(t *testing.T) {
	f, _ := newFilter(fixturePolicy())
	inner := `{"timezone":"Asia\u002fShanghai","id":"198.51.100.44"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(canary))
	message := map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": inner}, map[string]any{"type": "text", "text": "Asia%2FShanghai " + encoded}}}}
	b, _ := json.Marshal(message)
	var stats Counts
	out, e := f.message(b, &stats)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{hostIP, "Asia/Shanghai", "Asia%2FShanghai", encoded} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal("DECLARED_ENCODED_CANARY_LEAK")
		}
	}
	if stats.Replacements != 4 {
		t.Fatalf("expected four replacements, got %d", stats.Replacements)
	}
}
func TestBinaryAndProtocolLimitAreDeclared(t *testing.T) {
	f, _ := newFilter(fixturePolicy())
	binary := base64.StdEncoding.EncodeToString([]byte(canary))
	in := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"image","mimeType":"image/png","data":%q}]}}`, binary)
	var stats Counts
	out, e := f.message([]byte(in), &stats)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out, []byte(binary)) || stats.UninspectedBinaryBlocks != 1 || !bytes.Contains(out, []byte(`"isError":true`)) {
		t.Fatal("BINARY_OR_ERROR_SEMANTICS_CHANGED")
	}
	for _, bad := range []string{`{"jsonrpc":"2.0","id":1,"id":2,"result":{}}`, `{"jsonrpc":"2.0","result":{}} {}`, `not protocol`, strings.Repeat("x", maximumFrame+1)} {
		if _, e = f.message([]byte(bad), &stats); e == nil {
			t.Fatal("INVALID_FRAME_ACCEPTED")
		}
	}
}
func TestPolicyValidation(t *testing.T) {
	for _, policy := range []Policy{{3, nil}, {1, []Rule{{ID: "x", Value: "short"}}}, {1, []Rule{{ID: "x", Value: hostIP}, {ID: "x", Value: canary}}}, {1, []Rule{{ID: "x", Value: hostIP, Encodings: []string{"unsupported"}}}}, {1, []Rule{{ID: "a", Value: hostIP}, {ID: "b", Value: hostIP}}}} {
		if _, e := newFilter(policy); e == nil {
			t.Fatal("BAD_POLICY_ACCEPTED")
		}
	}
	if _, e := newFilter(Policy{1, nil}); e != nil {
		t.Fatal("EMPTY_EXPLICIT_RULESET_BREAKS_NORMAL_RESULTS")
	}
}

func TestUnsignedAndWrongSourceInstallerRejected(t *testing.T) {
	root := testDirectory(t)
	extension := ".exe"
	if runtime.GOOS == "darwin" {
		extension = ".pkg"
	}
	file := filepath.Join(root, "unsigned-fixture"+extension)
	os.WriteFile(file, bytes.Repeat([]byte("x"), 4096), 0600)
	for _, source := range []string{"http://claude.ai/download", "https://example.invalid/Claude", "https://claude.ai@evil.invalid/file", "https://claude.ai:8443/file", "https://claude.ai/download"} {
		if _, e := inspectInstaller(file, source); e == nil {
			t.Fatal("UNSIGNED_OR_WRONG_SOURCE_ACCEPTED")
		}
	}
}

func TestOfficialDownloadedArtifactSignatureOnly(t *testing.T) {
	file := os.Getenv("HONGAI_VALID_INSTALLER")
	if file == "" {
		t.Skip("REAL_DOWNLOADED_OFFICIAL_FIXTURE_NOT_PROVIDED")
	}
	result, e := inspectInstaller(file, os.Getenv("HONGAI_VALID_INSTALLER_SOURCE"))
	if e != nil {
		t.Fatal("OFFICIAL_DOWNLOAD_SIGNATURE_CHECK_FAILED", e)
	}
	if result["phase"] != "SIGNED_PUBLISHER_VERIFIED_INSTALL_ROLE_PENDING" || result["installerStarted"] != false || result["installationCompleted"] != false || result["initialLaunchProtected"] != false || result["bundledClaudeRuntime"] != false || result["sourceIsOperatorDeclaredNotBrowserHistoryProof"] != true {
		t.Fatal("SIGNATURE_CHECK_OVERSTATED_INSTALL_OR_PROTECTION")
	}
}
func TestCurrentUserProtectedStorage(t *testing.T) {
	root := testDirectory(t)
	plain := []byte(canary)
	sealed, e := platformSeal(plain, root)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("SECRET_STORED_PLAIN")
	}
	out, e := platformOpen(sealed, root)
	if e != nil || !bytes.Equal(out, plain) {
		t.Fatal("CURRENT_USER_DECRYPT_FAILED", e)
	}
	if _, e = platformOpen(sealed, root+"-different-environment"); e == nil {
		t.Fatal("CROSS_ENVIRONMENT_DECRYPT_ALLOWED")
	}
	sealed[len(sealed)-1] ^= 1
	if _, e = platformOpen(sealed, root); e == nil {
		t.Fatal("TAMPERED_BINDING_ACCEPTED")
	}
}

func makeRequest(t *testing.T, root, self string) (Request, []byte) {
	t.Helper()
	configFile := filepath.Join(root, "official-config-fixture.json")
	policyFile := filepath.Join(root, "policy.json")
	dataRoot := filepath.Join(root, "component-data")
	configuration := map[string]any{"preferences": map[string]any{"keep": "unchanged"}, "mcpServers": map[string]any{"files": map[string]any{"command": self, "args": []string{"-test.run=TestNativeUpstream", "--"}, "env": map[string]string{"HONGAI_UPSTREAM_FIXTURE": "1", "HONGAI_FIXTURE_ROOT": root, "UPSTREAM_SECRET": canary}, "extraClientSetting": true}, "remote-unselected": map[string]any{"url": "https://example.invalid/mcp"}}}
	original, _ := json.MarshalIndent(configuration, "", "    ")
	original = append([]byte{0xef, 0xbb, 0xbf}, original...)
	if e := os.WriteFile(configFile, original, 0600); e != nil {
		t.Fatal(e)
	}
	p, _ := json.Marshal(fixturePolicy())
	os.WriteFile(policyFile, p, 0600)
	return Request{configFile, dataRoot, policyFile, []string{"files"}}, original
}
func TestInstallIdempotenceAndExactRestore(t *testing.T) {
	root := testDirectory(t)
	upstream, _ := os.Executable()
	request, original := makeRequest(t, root, upstream)
	wrapper := filepath.Join(root, "wrapper-placeholder.exe")
	os.WriteFile(wrapper, []byte("CI config-only placeholder; never executed"), 0600)
	result, e := install(request, wrapper)
	if e != nil || result["phase"] != "INSTALLED" {
		t.Fatal(result, e)
	}
	after, _ := readSmall(request.ConfigFile)
	m, e := parseObject(after)
	if e != nil {
		t.Fatal(e)
	}
	servers := m["mcpServers"].(map[string]any)
	wrapped := servers["files"].(map[string]any)
	if wrapped["command"] == wrapper || !strings.HasPrefix(wrapped["command"].(string), request.DataRoot+string(os.PathSeparator)) || wrapped["env"] != nil || wrapped["extraClientSetting"] != true || servers["remote-unselected"].(map[string]any)["url"] != "https://example.invalid/mcp" {
		t.Fatal("ORIGINAL_CONFIGURATION_SEMANTICS_LOST")
	}
	args := wrapped["args"].([]any)
	binding, e := loadBinding(args[2].(string), request.DataRoot)
	if e != nil || binding.Env["UPSTREAM_SECRET"] != canary {
		t.Fatal("ENVIRONMENT_NOT_RESTORED_ONLY_FOR_UPSTREAM", e)
	}
	sealed, _ := readSmall(args[2].(string))
	if bytes.Contains(sealed, []byte(canary)) {
		t.Fatal("BINDING_EXPORTED_SECRET")
	}
	result, e = install(request, wrapper)
	if e != nil || result["phase"] != "ALREADY_INSTALLED" {
		t.Fatal("IDEMPOTENCE_FAILED", e)
	}
	result, e = restore(request.DataRoot)
	if e != nil || result["phase"] != "RESTORED" {
		t.Fatal(result, e)
	}
	restored, _ := readSmall(request.ConfigFile)
	if !bytes.Equal(restored, original) {
		t.Fatal("ORIGINAL_BYTES_NOT_RESTORED")
	}
}
func TestRestoreRejectsConcurrentCustomerEdit(t *testing.T) {
	root := testDirectory(t)
	upstream, _ := os.Executable()
	request, _ := makeRequest(t, root, upstream)
	os.WriteFile(filepath.Join(root, "wrapper.exe"), []byte("config-only fixture"), 0700)
	if _, e := install(request, filepath.Join(root, "wrapper.exe")); e != nil {
		t.Fatal(e)
	}
	changed := []byte(`{"customer":"changed-after-install"}`)
	os.WriteFile(request.ConfigFile, changed, 0600)
	if _, e := restore(request.DataRoot); e == nil {
		t.Fatal("CUSTOMER_CHANGE_OVERWRITTEN")
	}
	after, _ := os.ReadFile(request.ConfigFile)
	if !bytes.Equal(after, changed) {
		t.Fatal("RESTORE_CHANGED_CUSTOMER_FILE")
	}
}

func TestPendingReceiptRecovery(t *testing.T) {
	root := testDirectory(t)
	upstream, _ := os.Executable()
	request, _ := makeRequest(t, root, upstream)
	os.WriteFile(filepath.Join(root, "wrapper.exe"), []byte("config-only fixture"), 0700)
	if _, e := install(request, filepath.Join(root, "wrapper.exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(filepath.Join(request.DataRoot, "installation.json"), filepath.Join(request.DataRoot, "installation.pending.json")); e != nil {
		t.Fatal(e)
	}
	result, e := install(request, filepath.Join(root, "wrapper.exe"))
	if e != nil || result["phase"] != "INSTALLED_RECEIPT_RECOVERED" {
		t.Fatal("RECEIPT_NOT_RECOVERED_WITHOUT_REINSTALL", result, e)
	}
}

func TestNativeCLIInstallBridgeAndRestore(t *testing.T) {
	binary := os.Getenv("HONGAI_TOOL_BINARY")
	if binary == "" {
		t.Skip("NATIVE_EXECUTABLE_REQUIRED_FOR_CLI_ACCEPTANCE")
	}
	root := testDirectory(t)
	deploymentCopy := filepath.Join(root, "temporary-install-source")
	if runtime.GOOS == "windows" {
		deploymentCopy += ".exe"
	}
	if _, e := copyRuntime(binary, deploymentCopy); e != nil {
		t.Fatal(e)
	}
	binary = deploymentCopy
	upstream, _ := os.Executable()
	request, original := makeRequest(t, root, upstream)
	requestFile := filepath.Join(root, "request.json")
	data, _ := json.Marshal(request)
	os.WriteFile(requestFile, data, 0600)
	run := func(args ...string) []byte {
		t.Helper()
		c := exec.Command(binary, args...)
		out, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("NATIVE_CLI_FAILED: %s", out)
		}
		return out
	}
	if !bytes.Contains(run("install", "--request", requestFile), []byte("INSTALLED")) {
		t.Fatal("INSTALL_PHASE_MISSING")
	}
	after, _ := readSmall(request.ConfigFile)
	config, _ := parseObject(after)
	wrapped := config["mcpServers"].(map[string]any)["files"].(map[string]any)
	if e := os.Rename(deploymentCopy, deploymentCopy+".removed"); e != nil {
		t.Fatal("TEST_CANNOT_REMOVE_TEMPORARY_INSTALL_SOURCE", e)
	}
	binary = wrapped["command"].(string)
	rawArgs := wrapped["args"].([]any)
	args := []string{}
	for _, v := range rawArgs {
		args = append(args, v.(string))
	}
	command := exec.Command(wrapped["command"].(string), args...)
	command.Stdin = strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"text\":\"native CLI file edit preserved\"}}}\n")
	out, e := command.CombinedOutput()
	if e != nil {
		t.Fatal("NATIVE_BRIDGE_EXECUTION_FAILED", string(out))
	}
	if bytes.Contains(out, []byte(canary)) || bytes.Contains(out, []byte(hostIP)) || !bytes.Contains(out, []byte("native CLI file edit preserved")) {
		t.Fatal("NATIVE_BRIDGE_PRIVACY_OR_FUNCTION_FAILED")
	}
	if !bytes.Contains(run("install", "--request", requestFile), []byte("ALREADY_INSTALLED")) {
		t.Fatal("SECOND_INSTALL_NOT_IDEMPOTENT")
	}
	run("restore", "--data-root", request.DataRoot)
	restored, _ := os.ReadFile(request.ConfigFile)
	if !bytes.Equal(restored, original) {
		t.Fatal("NATIVE_RESTORE_LOST_ORIGINAL_BYTES")
	}
}
func TestFailedSelectionDoesNotModifyClientConfig(t *testing.T) {
	root := testDirectory(t)
	upstream, _ := os.Executable()
	request, original := makeRequest(t, root, upstream)
	request.ServerNames = []string{"remote-unselected"}
	if _, e := install(request, filepath.Join(root, "wrapper.exe")); e == nil {
		t.Fatal("UNSUPPORTED_REMOTE_SELECTED")
	}
	after, _ := os.ReadFile(request.ConfigFile)
	if !bytes.Equal(after, original) {
		t.Fatal("FAILED_INSTALL_CHANGED_CONFIG")
	}
}

func TestBridgeRealSubprocessAndNormalFileWork(t *testing.T) {
	root := testDirectory(t)
	self, _ := os.Executable()
	b := Binding{1, self, []string{"-test.run=TestNativeUpstream", "--"}, map[string]string{"HONGAI_UPSTREAM_FIXTURE": "1", "HONGAI_FIXTURE_ROOT": root, "UPSTREAM_SECRET": canary}, fixturePolicy()}
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"text\":\"const answer = 42; business 203.0.113.9\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n"
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stats, e := runBridge(ctx, b, strings.NewReader(input), &out)
	if e != nil {
		t.Fatal(e)
	}
	if stats.Messages != 3 || stats.Replacements < 4 {
		t.Fatal("UPSTREAM_RESULTS_NOT_PROCESSED", stats)
	}
	for _, s := range []string{canary, hostIP, "Asia/Shanghai"} {
		if bytes.Contains(out.Bytes(), []byte(s)) {
			t.Fatal("SUBPROCESS_CANARY_LEAK")
		}
	}
	if !bytes.Contains(out.Bytes(), []byte("const answer = 42;")) || !bytes.Contains(out.Bytes(), []byte("203.0.113.9")) {
		t.Fatal("NORMAL_WORK_LOST")
	}
	work, _ := os.ReadFile(filepath.Join(root, "work.txt"))
	if string(work) != "const answer = 42; business 203.0.113.9" {
		t.Fatal("FILE_WRITE_CONTENT_CHANGED")
	}
}

func nativeFixture() {
	fmt.Fprintln(os.Stderr, "MUST_NOT_EXPORT_STDERR "+os.Getenv("UPSTREAM_SECRET"))
	d := json.NewDecoder(os.Stdin)
	d.UseNumber()
	enc := json.NewEncoder(os.Stdout)
	for {
		var m map[string]any
		if d.Decode(&m) != nil {
			break
		}
		result := map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fixture", "version": "1"}}
		if m["method"] == "tools/call" {
			p := m["params"].(map[string]any)
			root := os.Getenv("HONGAI_FIXTURE_ROOT")
			file := filepath.Join(root, "work.txt")
			text := ""
			if p["name"] == "write_file" {
				args := p["arguments"].(map[string]any)
				text = args["text"].(string)
				if os.WriteFile(file, []byte(text), 0600) != nil {
					os.Exit(4)
				}
			} else {
				data, e := os.ReadFile(file)
				if e != nil {
					os.Exit(4)
				}
				text = string(data)
			}
			result = map[string]any{"isError": false, "content": []any{map[string]any{"type": "text", "text": "file operation OK: " + text + " | " + hostIP + " | " + canary + " | Asia/Shanghai"}}}
		}
		enc.Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": result})
	}
	os.Exit(0)
}
