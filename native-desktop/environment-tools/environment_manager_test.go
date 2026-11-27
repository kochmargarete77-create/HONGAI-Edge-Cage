package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureEnvironment(t *testing.T) (string, EnvironmentReceipt) {
	t.Helper()
	p := testDirectory(t)
	source := filepath.Join(p, "fake-runtime")
	if e := os.WriteFile(source, []byte("HONGAI_ENVIRONMENT_SYNTHETIC_RUNTIME_V1"), 0700); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(p, "environment")
	r, e := installEnvironment(root, source)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if runtime.GOOS == "darwin" {
			_ = exec.Command("/usr/bin/security", "delete-generic-password", "-a", keychainTestAccount(root), "-s", "com.hongai.environment.mcp-privacy").Run()
		}
	})
	return root, r
}
func fixtureSettings() EnvironmentSettings {
	return EnvironmentSettings{Version: 1, ProxyURL: "http://127.0.0.1:17896", ExpectedExit: "198.51.100.45", TimeZone: "America/Los_Angeles", HostAssessmentConfirmed: true}
}

func TestEnvironmentSettingsRejectRemoteAndUnsafeFallback(t *testing.T) {
	base := fixtureSettings()
	if e := validateEnvironmentSettings(base); e != nil {
		t.Fatal(e)
	}
	for _, proxy := range []string{"http://example.com:7890", "http://127.0.0.1:0", "http://user:password@127.0.0.1:7890", "socks5://127.0.0.1:7890", "http://127.0.0.1:7890/path", "http://127.0.0.1:7890?x=1", "http://localhost:7890", "http://127.0.0.1:99999"} {
		c := base
		c.ProxyURL = proxy
		if validateEnvironmentSettings(c) == nil {
			t.Fatalf("unsafe proxy accepted: %s", proxy)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "not-an-ip", "169.254.1.1"} {
		c := base
		c.ExpectedExit = ip
		if validateEnvironmentSettings(c) == nil {
			t.Fatal("nonpublic expected exit accepted")
		}
	}
}
func TestEnvironmentInstallRepeatRepairAndSafeUninstall(t *testing.T) {
	root, r := fixtureEnvironment(t)
	launcher := filepath.Join(root, "HONGAI-Environment.command")
	if runtime.GOOS == "windows" {
		launcher = filepath.Join(root, "HONGAI-Environment.cmd")
	}
	if e := os.Remove(launcher); e != nil {
		t.Fatal(e)
	}
	next, e := installEnvironment(root, r.Runtime)
	if e != nil || next.Runtime != r.Runtime {
		t.Fatalf("repeat install: %v", e)
	}
	if _, e = os.Stat(launcher); e != nil {
		t.Fatal("missing launcher was not repaired")
	}
	if e = saveEnvironmentSettings(root, fixtureSettings()); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(filepath.Dir(root), "customer-project.txt")
	_ = os.WriteFile(outside, []byte(canary), 0600)
	removed, e := removeEnvironment(root)
	if e != nil {
		t.Fatal(e)
	}
	recovery := removed["recoveryDirectory"].(string)
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("live directory was not moved")
	}
	if b, e := os.ReadFile(outside); e != nil || string(b) != canary {
		t.Fatal("customer file changed")
	}
	if e = os.Rename(recovery, root); e != nil {
		t.Fatal(e)
	}
	if got, e := loadEnvironmentSettings(root); e != nil || got != fixtureSettings() {
		t.Fatalf("recoverable restore failed: %v", e)
	}
}
func TestEnvironmentRejectsUnownedDirectoryAndTamperedRuntime(t *testing.T) {
	p := testDirectory(t)
	source := filepath.Join(p, "source")
	_ = os.WriteFile(source, []byte("fixture-source"), 0700)
	root := filepath.Join(p, "occupied")
	_ = os.Mkdir(root, 0700)
	_ = os.WriteFile(filepath.Join(root, "customer.txt"), []byte(canary), 0600)
	if _, e := installEnvironment(root, source); e == nil {
		t.Fatal("unowned customer directory accepted")
	}
	root, r := fixtureEnvironment(t)
	if e := os.WriteFile(r.Runtime, []byte("changed"), 0700); e != nil {
		t.Fatal(e)
	}
	originalSource := filepath.Join(filepath.Dir(root), "fake-runtime")
	if _, e := installEnvironment(root, originalSource); e == nil {
		t.Fatal("tampered installed runtime accepted")
	}
}
func TestEnvironmentOwnedInterruptedInstallAndStaleLocksRecover(t *testing.T) {
	p := testDirectory(t)
	root := filepath.Join(p, "environment")
	_ = os.Mkdir(root, 0700)
	if e := saveEnvironmentOwner(root); e != nil {
		t.Fatal(e)
	}
	_ = os.Mkdir(filepath.Join(root, "runtime-abandoned"), 0700)
	old := environmentLease{PID: 99999999, Nonce: "old-fixture", CreatedUTC: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(old)
	_ = os.WriteFile(filepath.Join(root, "environment-install.lock"), b, 0600)
	source := filepath.Join(p, "fake-runtime")
	_ = os.WriteFile(source, []byte("fixture executable"), 0700)
	if _, e := installEnvironment(root, source); e != nil {
		t.Fatal(e)
	}
	release, e := acquireEnvironmentLock(root, "workbench-active.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, e = acquireEnvironmentLock(root, "workbench-active.lock"); e == nil {
		t.Fatal("live lock not respected")
	}
	if _, e = removeEnvironment(root); e == nil {
		t.Fatal("active workbench uninstalled")
	}
}
func TestEnvironmentSettingsAreSealedAndOwnershipBound(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	s := fixtureSettings()
	if e := saveEnvironmentSettings(root, s); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, "environment-settings.sealed"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(s.ExpectedExit)) || bytes.Contains(b, []byte(s.ProxyURL)) {
		t.Fatal("settings stored in plaintext")
	}
	got, e := loadEnvironmentSettings(root)
	if e != nil || got != s {
		t.Fatalf("sealed settings roundtrip: %v", e)
	}
	other := testDirectory(t)
	if e = saveEnvironmentSettings(other, s); e == nil {
		t.Fatal("settings written to unowned location")
	}
}
func mockEnvironmentOperations(launches *atomic.Int32, healthy bool) environmentOperations {
	return environmentOperations{
		inventory: func(context.Context) (EnvironmentInventory, error) {
			return EnvironmentInventory{Platform: runtime.GOOS, Architecture: runtime.GOARCH, TimeZone: "America/Los_Angeles", Client: OfficialClient{Installed: true, Verified: true, ApplicationID: "SYNTHETIC_CLIENT"}}, nil
		},
		probe: func(context.Context, EnvironmentSettings) (ProxyObservation, error) {
			return ProxyObservation{Status: "SYNTHETIC_PROBE", Samples: 3, Matched: healthy, Scope: "FIXTURE_NOT_LIVE"}, nil
		},
		launch: func(context.Context, OfficialClient) error { launches.Add(1); return nil },
	}
}
func waitEnvironmentAction(t *testing.T, s *environmentServer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		busy := s.busy
		s.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond * 5)
	}
	t.Fatal("action did not finish")
}
func TestEnvironmentHTTPRejectsCrossOriginRebindingAndUnauthenticatedActions(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	var count atomic.Int32
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture-token", mockEnvironmentOperations(&count, true))
	for _, c := range []struct {
		host, token, origin, path string
		status                    int
	}{{"evil.example:19001", "fixture-token", s.baseURL, "/api/status", 403}, {"127.0.0.1:19001", "wrong-token", s.baseURL, "/api/status", 401}, {"127.0.0.1:19001", "fixture-token", "http://evil.example", "/api/action", 403}, {"127.0.0.1:19001", "fixture-token", s.baseURL, "/api/status?token=x", 400}} {
		r := httptest.NewRequest("POST", "http://"+c.host+c.path, strings.NewReader(`{"action":"launch"}`))
		r.Host = c.host
		r.Header.Set("Authorization", "Bearer "+c.token)
		r.Header.Set("Origin", c.origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatalf("unexpected reject %d instead of %d", w.Code, c.status)
		}
	}
	if count.Load() != 0 {
		t.Fatal("unauthorized launch occurred")
	}
	r := httptest.NewRequest("GET", s.baseURL+"/", nil)
	r.Host = "127.0.0.1:19001"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || strings.Contains(w.Body.String(), s.token) {
		t.Fatal("session token leaked into public HTML or frame protection absent")
	}
}
func TestEnvironmentLaunchRequiresHostApprovalHealthyProxyAndVerifiedClient(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	var launches atomic.Int32
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture", mockEnvironmentOperations(&launches, false))
	if e := s.startAction("launch"); e == nil {
		t.Fatal("launch without approved settings accepted")
	}
	cfg := fixtureSettings()
	cfg.HostAssessmentConfirmed = false
	s.settings = &cfg
	if e := s.startAction("launch"); e == nil {
		t.Fatal("host approval absent but launch accepted")
	}
	cfg.HostAssessmentConfirmed = true
	if e := s.startAction("launch"); e != nil {
		t.Fatal(e)
	}
	waitEnvironmentAction(t, s)
	if launches.Load() != 0 {
		t.Fatal("unhealthy proxy still launched client")
	}
	s.ops = mockEnvironmentOperations(&launches, true)
	if e := s.startAction("launch"); e != nil {
		t.Fatal(e)
	}
	waitEnvironmentAction(t, s)
	if launches.Load() != 1 || s.lastCode != "OFFICIAL_ACTIVATION_REQUESTED_ACCOUNT_TEST_PENDING" {
		t.Fatal("normal activation path failed")
	}
}
func TestEnvironmentProbeUsesExplicitProxyWithoutDirectFallback(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "CONNECT" || r.Host != "www.cloudflare.com:443" {
			t.Error("unexpected proxy request")
		}
		w.WriteHeader(502)
	}))
	defer proxy.Close()
	cfg := fixtureSettings()
	cfg.ProxyURL = proxy.URL
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	r, e := probeEnvironmentProxy(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 || r.DirectFallback || r.Matched || r.Status != "PROXY_OR_TRACE_UNAVAILABLE" {
		t.Fatal("failed proxy did not remain closed")
	}
}
func TestEnvironmentNativeInventoryDoesNotReadAccountState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, e := inventoryEnvironment(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if r.AccountRead || r.HostNetworkModified || r.HardwareIdentityModified {
		t.Fatal("inventory scope changed")
	}
	if os.Getenv("HONGAI_REQUIRE_REGISTERED_CLIENT") == "1" && (!r.Client.Installed || !r.Client.Verified || r.Client.Version == "") {
		t.Fatal("native officially installed fixture was not discovered and verified")
	}
}
func TestEnvironmentEventLogRecordsCodesWithoutSensitiveValues(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	for n := 0; n < 3; n++ {
		if e := appendEnvironmentEvent(root, "FIXTURE", "NO_ACCOUNT_READ"); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "environment-events.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(canary)) || bytes.Contains(b, []byte(fixtureSettings().ExpectedExit)) {
		t.Fatal("sensitive value leaked")
	}
	prev := ""
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var v struct {
			Event json.RawMessage `json:"event"`
			Hash  string          `json:"hash"`
		}
		if e = json.Unmarshal(line, &v); e != nil {
			t.Fatal(e)
		}
		var ev struct {
			PreviousHash string `json:"previousHash"`
		}
		if e = json.Unmarshal(v.Event, &ev); e != nil || ev.PreviousHash != prev || digest(v.Event) != v.Hash {
			t.Fatal("event chain invalid")
		}
		prev = v.Hash
	}
}
func TestEnvironmentRealCLIInstallSavedLaunchAndRecoverableUninstall(t *testing.T) {
	binary := os.Getenv("HONGAI_TOOL_BINARY")
	if binary == "" {
		t.Fatal("BUILT_NATIVE_BINARY_REQUIRED")
	}
	p := testDirectory(t)
	root := filepath.Join(p, "environment")
	defer func() {
		if runtime.GOOS == "darwin" {
			_ = exec.Command("/usr/bin/security", "delete-generic-password", "-a", keychainTestAccount(root), "-s", "com.hongai.environment.mcp-privacy").Run()
		}
	}()
	run := func(args ...string) []byte {
		t.Helper()
		out, e := exec.Command(binary, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("CLI command failed %v: %s", e, out)
		}
		return out
	}
	var receipt EnvironmentReceipt
	if e := json.Unmarshal(run("environment", "install", "--root", root), &receipt); e != nil {
		t.Fatal(e)
	}
	child := exec.Command(receipt.Runtime, "environment", "open", "--root", root, "--no-browser", "--minutes", "1")
	if e := child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var address workbenchAddress
	var client = http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		b, e := readSmall(filepath.Join(root, "workbench-address.sealed"))
		if e == nil {
			b, e = platformOpen(b, root)
			if e == nil && json.Unmarshal(b, &address) == nil {
				req, _ := http.NewRequest("GET", address.BaseURL+"/api/ping", nil)
				req.Header.Set("Authorization", "Bearer "+address.Token)
				resp, e := client.Do(req)
				if e == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						ready = true
						break
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("native workbench did not become ready")
	}
	// A second launch reuses the live local workbench instead of starting another server.
	run("environment", "open", "--root", root, "--no-browser", "--minutes", "1")
	req, _ := http.NewRequest("POST", address.BaseURL+"/api/stop", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+address.Token)
	req.Header.Set("Origin", address.BaseURL)
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if e = child.Wait(); e != nil {
		t.Fatal(e)
	}
	var removed map[string]any
	uninstallOut, uninstallError := exec.Command(receipt.Runtime, "environment", "uninstall", "--root", root).CombinedOutput()
	if uninstallError != nil {
		t.Fatalf("installed runtime uninstall failed: %v %s", uninstallError, uninstallOut)
	}
	if e = json.Unmarshal(uninstallOut, &removed); e != nil {
		t.Fatal(e)
	}
	if removed["status"] != "RECOVERABLY_REMOVED" {
		t.Fatal("CLI recoverable uninstall failed")
	}
}

func TestEnvironmentLogRotationRetainsLinkAndRejectsCorruptTail(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	if e := appendEnvironmentEvent(root, "FIXTURE", "START"); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "environment-events.jsonl")
	b, _ := os.ReadFile(p)
	oldHash, e := environmentLastEventHash(p)
	if e != nil {
		t.Fatal(e)
	}
	large := append(bytes.Repeat([]byte(" "), (2<<20)+16), b...)
	if e = os.WriteFile(p, large, 0600); e != nil {
		t.Fatal(e)
	}
	if e = appendEnvironmentEvent(root, "FIXTURE", "AFTER_ROTATION"); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var entry struct {
		Event struct {
			PreviousHash string `json:"previousHash"`
		} `json:"event"`
	}
	if json.Unmarshal(b, &entry) != nil || entry.Event.PreviousHash != oldHash {
		t.Fatal("rotation lost previous event link")
	}
	if e = os.WriteFile(p, []byte("BROKEN_LAST_RECORD\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if appendEnvironmentEvent(root, "FIXTURE", "MUST_NOT_REWRITE") == nil {
		t.Fatal("corrupt event tail silently replaced")
	}
}
func TestEnvironmentStoppingCancelsAndDrainsOwnedOperations(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	started := make(chan struct{})
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture", environmentOperations{inventory: func(ctx context.Context) (EnvironmentInventory, error) {
		close(started)
		<-ctx.Done()
		return EnvironmentInventory{}, ctx.Err()
	}})
	if e := s.startAction("inventory"); e != nil {
		t.Fatal(e)
	}
	<-started
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	s.workers.Wait()
	if e := s.startAction("inventory"); e == nil {
		t.Fatal("work began after shutdown")
	}
}

func TestEnvironmentUninstallRefusesExtraCustomerFiles(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	p := filepath.Join(root, "customer-project.txt")
	if e := os.WriteFile(p, []byte(canary), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := removeEnvironment(root); e == nil {
		t.Fatal("extra customer file silently moved")
	}
	if b, e := os.ReadFile(p); e != nil || string(b) != canary {
		t.Fatal("customer file changed")
	}
}
