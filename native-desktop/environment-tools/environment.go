package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const environmentVersion = "0.1.0-environment-preview"

type EnvironmentSettings struct {
	Version                 int    `json:"version"`
	ProxyURL                string `json:"proxyUrl"`
	ExpectedExit            string `json:"expectedExit"`
	TimeZone                string `json:"timeZone"`
	HostAssessmentConfirmed bool   `json:"hostAssessmentConfirmed"`
}
type EnvironmentReceipt struct {
	Schema          string `json:"schema"`
	Version         string `json:"version"`
	Root            string `json:"root"`
	Runtime         string `json:"runtime"`
	RuntimeSHA      string `json:"runtimeSha256"`
	PreviousRuntime string `json:"previousRuntime,omitempty"`
	CreatedUTC      string `json:"createdUtc"`
}
type OfficialClient struct {
	Installed        bool   `json:"installed"`
	Verified         bool   `json:"verified"`
	Kind             string `json:"kind"`
	Version          string `json:"version"`
	Architecture     string `json:"architecture"`
	ApplicationID    string `json:"applicationId,omitempty"`
	Path             string `json:"path,omitempty"`
	ProfilePath      string `json:"profilePath,omitempty"`
	ProfileExists    bool   `json:"profileExists"`
	ProfileSelection string `json:"profileSelection"`
}
type EnvironmentInventory struct {
	Schema                   string         `json:"schema"`
	Platform                 string         `json:"platform"`
	Architecture             string         `json:"architecture"`
	TimeZone                 string         `json:"timeZone"`
	Client                   OfficialClient `json:"client"`
	AccountRead              bool           `json:"accountRead"`
	HostNetworkModified      bool           `json:"hostNetworkModified"`
	HardwareIdentityModified bool           `json:"hardwareIdentityModified"`
	CollectedUTC             string         `json:"collectedUtc"`
}
type ProxyObservation struct {
	Status         string `json:"status"`
	Samples        int    `json:"samples"`
	Matched        bool   `json:"matched"`
	Country        string `json:"country,omitempty"`
	ExitID         string `json:"exitId,omitempty"`
	Scope          string `json:"scope"`
	DirectFallback bool   `json:"directFallback"`
	ObservedUTC    string `json:"observedUtc"`
}

func validateEnvironmentSettings(s EnvironmentSettings) error {
	if s.Version != 1 {
		return errors.New("ENVIRONMENT_SETTINGS_VERSION_UNSUPPORTED")
	}
	u, e := url.Parse(s.ProxyURL)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Port() == "" {
		return errors.New("LOOPBACK_HTTP_MIXED_PROXY_REQUIRED")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.IsLoopback() {
		return errors.New("PROXY_MUST_BE_LITERAL_LOOPBACK")
	}
	if _, e = net.ResolveTCPAddr("tcp", u.Host); e != nil {
		return errors.New("PROXY_PORT_INVALID")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return errors.New("PROXY_PORT_INVALID")
	}
	exit, e := netip.ParseAddr(s.ExpectedExit)
	if e != nil || !exit.Is4() || !exit.IsGlobalUnicast() || exit.IsPrivate() || exit.IsLoopback() || exit.IsLinkLocalUnicast() {
		return errors.New("APPROVED_FINAL_PUBLIC_IPV4_REQUIRED")
	}
	if s.TimeZone != "America/Los_Angeles" && s.TimeZone != "America/New_York" && s.TimeZone != "America/Chicago" && s.TimeZone != "America/Denver" && s.TimeZone != "America/Phoenix" && s.TimeZone != "America/Anchorage" && s.TimeZone != "Pacific/Honolulu" {
		return errors.New("APPROVED_SUPPORTED_IANA_TIME_ZONE_REQUIRED")
	}
	return nil
}

func environmentRoot(p string, create bool) (string, error) {
	if !filepath.IsAbs(p) {
		return "", errors.New("ABSOLUTE_ENVIRONMENT_ROOT_REQUIRED")
	}
	p = filepath.Clean(p)
	if filepath.Dir(p) == p || len(filepath.Base(p)) < 4 {
		return "", errors.New("DEDICATED_ENVIRONMENT_DIRECTORY_REQUIRED")
	}
	if _, e := realPath(filepath.Dir(p), true); e != nil {
		return "", e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) && create {
		if e = os.Mkdir(p, 0700); e != nil {
			return "", errors.New("ENVIRONMENT_DIRECTORY_CREATE_FAILED")
		}
	}
	return realPath(p, true)
}

func installEnvironment(root, self string) (EnvironmentReceipt, error) {
	var empty EnvironmentReceipt
	if e := assertCustomerIdentity(); e != nil {
		return empty, e
	}
	root, e := environmentRoot(root, true)
	if e != nil {
		return empty, e
	}
	release, e := acquireEnvironmentLock(root, "environment-install.lock")
	if e != nil {
		return empty, e
	}
	defer release()
	receiptPath := filepath.Join(root, "environment-receipt.json")
	var old EnvironmentReceipt
	if _, e = os.Stat(receiptPath); e == nil {
		if e = decodeFile(receiptPath, &old); e != nil || old.Schema != "hongai.environment-install.v1" || !samePath(old.Root, root) {
			return empty, errors.New("EXISTING_ENVIRONMENT_RECEIPT_INVALID")
		}
		if !ownedEnvironmentRuntime(root, old.Runtime) {
			return empty, errors.New("ENVIRONMENT_RUNTIME_OWNERSHIP_INVALID")
		}
	} else if !validEnvironmentOwner(root) {
		entries, e := os.ReadDir(root)
		if e != nil {
			return empty, errors.New("ENVIRONMENT_DIRECTORY_UNREADABLE")
		}
		for _, entry := range entries {
			if entry.Name() != "environment-install.lock" && entry.Name() != ".environment-operations.guard" {
				return empty, errors.New("NONEMPTY_UNOWNED_ENVIRONMENT_DIRECTORY")
			}
		}
	}
	if e = saveEnvironmentOwner(root); e != nil {
		return empty, e
	}
	if old.Runtime != "" && ownedEnvironmentRuntime(root, self) && !samePath(self, old.Runtime) {
		actual, e := readRuntimeBytes(old.Runtime)
		if e != nil || digest(actual) != old.RuntimeSHA {
			return empty, errors.New("INSTALLED_ENVIRONMENT_RUNTIME_CHANGED")
		}
		return old, nil
	}
	b, e := readRuntimeBytes(self)
	if e != nil {
		return empty, e
	}
	sourceSHA := digest(b)
	if old.RuntimeSHA == sourceSHA && old.Runtime != "" {
		actual, e := readRuntimeBytes(old.Runtime)
		if e != nil || digest(actual) != sourceSHA {
			return empty, errors.New("INSTALLED_ENVIRONMENT_RUNTIME_CHANGED")
		}
		if e = writeEnvironmentLauncher(root, old.Runtime); e != nil {
			return empty, e
		}
		return old, nil
	}
	stage := filepath.Join(root, "runtime-"+randomName())
	if e = os.Mkdir(stage, 0700); e != nil {
		return empty, errors.New("ENVIRONMENT_RUNTIME_STAGE_CREATE_FAILED")
	}
	name := "hongai-environment"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	target := filepath.Join(stage, name)
	h, e := copyRuntime(self, target)
	if e != nil {
		return empty, e
	}
	if e = preserveEnvironmentOrigin(self, target); e != nil {
		return empty, e
	}
	if h != sourceSHA {
		return empty, errors.New("ENVIRONMENT_RUNTIME_SOURCE_CHANGED")
	}
	r := EnvironmentReceipt{Schema: "hongai.environment-install.v1", Version: environmentVersion, Root: root, Runtime: target, RuntimeSHA: h, PreviousRuntime: old.Runtime, CreatedUTC: time.Now().UTC().Format(time.RFC3339)}
	encoded, _ := json.MarshalIndent(r, "", "  ")
	if e = atomicReplace(receiptPath, encoded); e != nil {
		return empty, e
	}
	if e = writeEnvironmentLauncher(root, target); e != nil {
		return empty, e
	}
	return r, nil
}
func readRuntimeBytes(p string) ([]byte, error) {
	p, e := realPath(p, false)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, errors.New("ENVIRONMENT_RUNTIME_UNREADABLE")
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || s.Size() < 1 || s.Size() > 32<<20 {
		return nil, errors.New("ENVIRONMENT_RUNTIME_SIZE_INVALID")
	}
	b, e := io.ReadAll(io.LimitReader(f, 32<<20+1))
	if e != nil || len(b) > 32<<20 {
		return nil, errors.New("ENVIRONMENT_RUNTIME_READ_FAILED")
	}
	return b, nil
}
func ownedEnvironmentRuntime(root, p string) bool {
	rel, e := filepath.Rel(root, p)
	if e != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return false
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	return len(parts) == 2 && strings.HasPrefix(parts[0], "runtime-") && (parts[1] == "hongai-environment" || parts[1] == "hongai-environment.exe")
}
func saveEnvironmentSettings(root string, s EnvironmentSettings) error {
	if !validEnvironmentOwner(root) {
		return errors.New("ENVIRONMENT_OWNERSHIP_REQUIRED")
	}
	if e := validateEnvironmentSettings(s); e != nil {
		return e
	}
	b, _ := json.Marshal(s)
	sealed, e := platformSeal(b, root)
	if e != nil {
		return e
	}
	return atomicReplace(filepath.Join(root, "environment-settings.sealed"), sealed)
}
func loadEnvironmentSettings(root string) (EnvironmentSettings, error) {
	var s EnvironmentSettings
	b, e := readSmall(filepath.Join(root, "environment-settings.sealed"))
	if e != nil {
		return s, e
	}
	b, e = platformOpen(b, root)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, errors.New("ENVIRONMENT_SETTINGS_INVALID")
	}
	return s, validateEnvironmentSettings(s)
}
func inventoryEnvironment(ctx context.Context) (EnvironmentInventory, error) {
	i := EnvironmentInventory{Schema: "hongai.environment-inventory.v1", Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedUTC: time.Now().UTC().Format(time.RFC3339)}
	client, tz, e := discoverOfficialClient(ctx)
	i.Client = client
	i.TimeZone = tz
	return i, e
}
func probeEnvironmentProxy(ctx context.Context, s EnvironmentSettings) (ProxyObservation, error) {
	r := ProxyObservation{Status: "NOT_TESTED", Scope: "HTTPS trace through approved loopback proxy only; NOT proof of all native Claude traffic", ObservedUTC: time.Now().UTC().Format(time.RFC3339)}
	if e := validateEnvironmentSettings(s); e != nil {
		return r, e
	}
	u, _ := url.Parse(s.ProxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(u), DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, TLSHandshakeTimeout: 6 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 16384}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("PROBE_REDIRECT_REJECTED") }}
	for n := 0; n < 3; n++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
		resp, e := client.Do(req)
		if e != nil {
			r.Status = "PROXY_OR_TRACE_UNAVAILABLE"
			return r, nil
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 32769))
		resp.Body.Close()
		if e != nil || len(b) > 32768 || resp.StatusCode != 200 {
			r.Status = "TRACE_RESPONSE_NOT_ACCEPTED"
			return r, nil
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				fields[parts[0]] = strings.TrimSpace(parts[1])
			}
		}
		if fields["ip"] != s.ExpectedExit {
			r.Status = "FINAL_EXIT_MISMATCH"
			return r, nil
		}
		r.Samples++
		r.ExitID = digest([]byte("hongai-public-exit-v1|" + fields["ip"]))[:16]
		if len(fields["loc"]) == 2 {
			r.Country = fields["loc"]
		}
	}
	r.Status = "THREE_TRACE_SAMPLES_MATCH"
	r.Matched = true
	return r, nil
}
func removeEnvironment(root string) (map[string]any, error) {
	root, e := environmentRoot(root, false)
	if e != nil {
		return nil, e
	}
	var r EnvironmentReceipt
	if e = decodeFile(filepath.Join(root, "environment-receipt.json"), &r); e != nil || r.Schema != "hongai.environment-install.v1" || !samePath(r.Root, root) || !ownedEnvironmentRuntime(root, r.Runtime) || !validEnvironmentOwner(root) {
		return nil, errors.New("ENVIRONMENT_OWNERSHIP_NOT_VERIFIED")
	}
	unlock, e := environmentTransitionGuard(root)
	if e != nil {
		return nil, e
	}
	defer unlock()
	for _, name := range []string{"environment-install.lock", "environment-events.lock"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			var lease environmentLease
			if decodeFile(filepath.Join(root, name), &lease) != nil || lease.PID <= 0 || lease.Nonce == "" || environmentProcessAlive(lease.PID) {
				return nil, errors.New("ENVIRONMENT_OPERATION_ACTIVE_RETRY_UNINSTALL_LATER")
			}
			if err = os.Remove(filepath.Join(root, name)); err != nil {
				return nil, errors.New("STALE_OWNED_LEASE_REMOVE_FAILED")
			}
		} else if !os.IsNotExist(err) {
			return nil, errors.New("ENVIRONMENT_LEASE_UNREADABLE")
		}
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, errors.New("ENVIRONMENT_DIRECTORY_UNREADABLE")
	}
	allowed := map[string]bool{"environment-receipt.json": true, "environment-owner.json": true, "environment-settings.sealed": true, "workbench-address.sealed": true, "HONGAI-Environment.cmd": true, "HONGAI-Environment.command": true, "environment-events.jsonl": true, "environment-events.jsonl.1": true, "environment-events.jsonl.2": true, "environment-events.jsonl.3": true, "environment-install.lock": true, "workbench-active.lock": true, "environment-events.lock": true, ".environment-operations.guard": true, "mcp": true, ".DS_Store": true}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("ENVIRONMENT_LINK_REQUIRES_MANUAL_REVIEW")
		}
		name := entry.Name()
		if allowed[name] {
			continue
		}
		if entry.IsDir() && strings.HasPrefix(name, "runtime-") {
			children, err := os.ReadDir(filepath.Join(root, name))
			if err != nil {
				return nil, errors.New("ENVIRONMENT_RUNTIME_DIRECTORY_UNREADABLE")
			}
			for _, child := range children {
				if child.IsDir() || child.Type()&os.ModeSymlink != 0 || (child.Name() != "hongai-environment" && child.Name() != "hongai-environment.exe" && child.Name() != ".DS_Store") {
					return nil, errors.New("EXTRA_CUSTOMER_FILES_REQUIRE_REVIEW_BEFORE_UNINSTALL")
				}
			}
			continue
		}
		return nil, errors.New("EXTRA_CUSTOMER_FILES_REQUIRE_REVIEW_BEFORE_UNINSTALL")
	}
	if _, e = os.Lstat(filepath.Join(root, "workbench-active.lock")); e == nil {
		var lease environmentLease
		if decodeFile(filepath.Join(root, "workbench-active.lock"), &lease) != nil || lease.PID <= 0 || lease.Nonce == "" || environmentProcessAlive(lease.PID) {
			return nil, errors.New("CLOSE_WORKBENCH_BEFORE_RECOVERABLE_UNINSTALL")
		}
		if e = os.Remove(filepath.Join(root, "workbench-active.lock")); e != nil {
			return nil, errors.New("STALE_WORKBENCH_LOCK_REMOVE_FAILED")
		}
	} else if !os.IsNotExist(e) {
		return nil, errors.New("WORKBENCH_LEASE_UNREADABLE")
	}
	if _, e = os.Lstat(filepath.Join(root, "mcp", "installation.json")); e == nil {
		if _, e = restore(filepath.Join(root, "mcp")); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, errors.New("MCP_RECEIPT_UNREADABLE")
	}
	target := root + ".removed-" + randomName()
	if !filepath.IsAbs(target) || !samePath(filepath.Dir(root), filepath.Dir(target)) {
		return nil, errors.New("RECOVERY_TARGET_OUTSIDE_EXPECTED_PARENT")
	}
	if e = os.Rename(root, target); e != nil {
		return nil, errors.New("RECOVERABLE_ENVIRONMENT_RENAME_FAILED")
	}
	return map[string]any{"status": "RECOVERABLY_REMOVED", "recoveryDirectory": target, "officialClaudeRemoved": false, "accountStateRemoved": false, "networkModified": false}, nil
}
func executeEnvironment(args []string) error {
	command := "open"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	f := flag.NewFlagSet("environment-"+command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "", "Dedicated local application directory")
	request := f.String("request", "", "Settings JSON")
	noBrowser := f.Bool("no-browser", false, "Do not open the local user interface")
	minutes := f.Int("minutes", 120, "Maximum workbench runtime")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return errors.New("ENVIRONMENT_ARGUMENTS_INVALID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if command == "inventory" {
		r, e := inventoryEnvironment(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if *root == "" {
		var e error
		*root, e = defaultEnvironmentRoot()
		if e != nil {
			return e
		}
	}
	switch command {
	case "install":
		self, e := os.Executable()
		if e != nil {
			return e
		}
		r, e := installEnvironment(*root, self)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	case "configure":
		var s EnvironmentSettings
		if e := decodeFile(*request, &s); e != nil {
			return e
		}
		r, e := environmentRoot(*root, false)
		if e != nil {
			return e
		}
		if e = saveEnvironmentSettings(r, s); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "SAVED_WITHOUT_HOST_NETWORK_CHANGE"})
	case "probe":
		r, e := environmentRoot(*root, false)
		if e != nil {
			return e
		}
		s, e := loadEnvironmentSettings(r)
		if e != nil {
			return e
		}
		result, e := probeEnvironmentProxy(ctx, s)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "uninstall":
		r, e := removeEnvironment(*root)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	case "use":
		if *minutes < 1 || *minutes > 480 {
			return errors.New("WORKBENCH_DURATION_MUST_BE_1_TO_480_MINUTES")
		}
		self, e := os.Executable()
		if e != nil {
			return e
		}
		receipt, e := installEnvironment(*root, self)
		if e != nil {
			return e
		}
		cfg, e := loadEnvironmentSettings(receipt.Root)
		if e != nil || !cfg.HostAssessmentConfirmed {
			return serveEnvironment(receipt.Root, *noBrowser, time.Duration(*minutes)*time.Minute)
		}
		inv, e := inventoryEnvironment(ctx)
		if e != nil || !inv.Client.Installed || !inv.Client.Verified || inv.TimeZone != cfg.TimeZone {
			return serveEnvironment(receipt.Root, *noBrowser, time.Duration(*minutes)*time.Minute)
		}
		proof, e := probeEnvironmentProxy(ctx, cfg)
		if e != nil || !proof.Matched {
			_ = appendEnvironmentEvent(receipt.Root, "DAILY_LAUNCH", "HEALTH_NOT_ACCEPTED_NO_LAUNCH")
			return serveEnvironment(receipt.Root, *noBrowser, time.Duration(*minutes)*time.Minute)
		}
		if e = appendEnvironmentEvent(receipt.Root, "DAILY_LAUNCH", "VERIFIED_ENTRY_ACTIVATION_REQUESTED"); e != nil {
			return e
		}
		if e = launchOfficialClient(ctx, inv.Client); e != nil {
			return e
		}
		if e = appendEnvironmentEvent(receipt.Root, "DAILY_LAUNCH", "OFFICIAL_ACTIVATION_REQUESTED_ACCOUNT_TEST_PENDING"); e != nil {
			return errors.New("OFFICIAL_ACTIVATION_REQUESTED_AUDIT_REVIEW_REQUIRED")
		}
		return nil
	case "open":
		if *minutes < 1 || *minutes > 480 {
			return errors.New("WORKBENCH_DURATION_MUST_BE_1_TO_480_MINUTES")
		}
		self, e := os.Executable()
		if e != nil {
			return e
		}
		receipt, e := installEnvironment(*root, self)
		if e != nil {
			return e
		}
		return serveEnvironment(receipt.Root, *noBrowser, time.Duration(*minutes)*time.Minute)
	default:
		return fmt.Errorf("ENVIRONMENT_COMMAND_NOT_SUPPORTED")
	}
}
