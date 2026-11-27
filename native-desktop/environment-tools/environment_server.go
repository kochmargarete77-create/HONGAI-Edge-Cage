package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed environment_ui.html
var environmentUI []byte

//go:embed environment_ui.js
var environmentJS []byte

type workbenchAddress struct {
	PID      int    `json:"pid"`
	BaseURL  string `json:"baseUrl"`
	Token    string `json:"token"`
	Instance string `json:"instance"`
}
type environmentOperations struct {
	inventory func(context.Context) (EnvironmentInventory, error)
	probe     func(context.Context, EnvironmentSettings) (ProxyObservation, error)
	launch    func(context.Context, OfficialClient) error
}
type environmentServer struct {
	root, token, baseURL, instance string
	mu                             sync.Mutex
	busy                           bool
	operation                      string
	lastCode                       string
	inventory                      *EnvironmentInventory
	probe                          *ProxyObservation
	settings                       *EnvironmentSettings
	ops                            environmentOperations
	shutdown                       func()
	ctx                            context.Context
	cancel                         context.CancelFunc
	workers                        sync.WaitGroup
	closing                        bool
}

func newEnvironmentServer(root, base, token string, ops environmentOperations) *environmentServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &environmentServer{root: root, baseURL: base, token: token, instance: randomName(), ops: ops, lastCode: "READY_FOR_INVENTORY", ctx: ctx, cancel: cancel}
	if c, e := loadEnvironmentSettings(root); e == nil {
		s.settings = &c
	}
	return s
}
func apiError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": code})
}
func safeEnvironmentCode(e error) string {
	if e == nil {
		return "SUCCESS"
	}
	c := e.Error()
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return "OPERATION_FAILED_RAW_DETAILS_NOT_LOGGED"
		}
	}
	if len(c) > 100 || len(c) == 0 {
		return "OPERATION_FAILED_RAW_DETAILS_NOT_LOGGED"
	}
	return c
}

func environmentJSONContentType(r *http.Request) bool {
	media, parameters, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return false
	}
	for name, value := range parameters {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// Reject an oversized valid prefix, duplicate members, case aliases and trailing
// JSON instead of accepting whichever value encoding/json happens to choose.
func readEnvironmentObject(r *http.Request, maximum int64, allowed ...string) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r.Body, maximum+1))
	if e != nil || int64(len(b)) > maximum {
		return nil, errors.New("REQUEST_BODY_LIMIT_EXCEEDED")
	}
	object, e := parseObject(b)
	if e != nil {
		return nil, errors.New("REQUEST_JSON_INVALID")
	}
	for member := range object {
		permitted := false
		for _, name := range allowed {
			if member == name {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, errors.New("REQUEST_FIELD_NOT_SUPPORTED")
		}
	}
	return b, nil
}

func (s *environmentServer) markClosing() {
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.mu.Unlock()
}
func (s *environmentServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	uHost := strings.TrimPrefix(s.baseURL, "http://")
	if r.Host != uHost {
		apiError(w, 403, "LOCAL_HOST_MISMATCH")
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "QUERY_ARGUMENTS_NOT_SUPPORTED")
		return
	}
	if r.URL.Path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(environmentUI)
		return
	}
	if r.URL.Path == "/workbench.js" && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(environmentJS)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		apiError(w, 404, "NOT_FOUND")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		apiError(w, 401, "LOCAL_SESSION_AUTHENTICATION_REQUIRED")
		return
	}
	if r.Method != "GET" && r.Header.Get("Origin") != s.baseURL {
		apiError(w, 403, "LOCAL_ORIGIN_MISMATCH")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch {
	case r.URL.Path == "/api/ping" && r.Method == "GET":
		_ = json.NewEncoder(w).Encode(map[string]any{"instance": s.instance, "version": environmentVersion})
	case r.URL.Path == "/api/status" && r.Method == "GET":
		s.mu.Lock()
		snapshot := map[string]any{"version": environmentVersion, "busy": s.busy, "operation": s.operation, "lastCode": s.lastCode, "inventory": s.inventory, "probe": s.probe, "settings": s.settings, "capabilities": map[string]bool{"officialPackageIdentityPreserved": true, "hostNetworkMutation": false, "accountRequiredForPreparation": false, "hardwareSimulation": false, "nativeAllEgressEnforcement": false, "authenticatedBusinessAccepted": false, "fullEnvironmentAccepted": false}}
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(snapshot)
	case r.URL.Path == "/api/settings" && r.Method == "POST":
		if !environmentJSONContentType(r) {
			apiError(w, 415, "JSON_CONTENT_TYPE_REQUIRED")
			return
		}
		var c EnvironmentSettings
		b, e := readEnvironmentObject(r, 8192, "version", "proxyUrl", "expectedExit", "timeZone", "hostAssessmentConfirmed")
		if e != nil {
			apiError(w, 400, safeEnvironmentCode(e))
			return
		}
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.DisallowUnknownFields()
		if e = decoder.Decode(&c); e != nil {
			apiError(w, 400, "SETTINGS_FIELDS_INVALID")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closing || s.ctx.Err() != nil {
			apiError(w, 409, "WORKBENCH_IS_STOPPING")
			return
		}
		if s.busy {
			apiError(w, 409, "OPERATION_ALREADY_RUNNING")
			return
		}
		if e = appendEnvironmentEvent(s.root, "SETTINGS", "SAVE_REQUESTED"); e != nil {
			apiError(w, 409, safeEnvironmentCode(e))
			return
		}
		if e = saveEnvironmentSettings(s.root, c); e != nil {
			apiError(w, 400, safeEnvironmentCode(e))
			return
		}
		s.settings = &c
		s.probe = nil
		s.lastCode = "SETTINGS_SAVED_NO_HOST_CHANGE"
		if appendEnvironmentEvent(s.root, "SETTINGS", "SAVED_NO_HOST_CHANGE") != nil {
			s.lastCode = "SETTINGS_SAVED_AUDIT_REVIEW_REQUIRED"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": s.lastCode})
	case r.URL.Path == "/api/action" && r.Method == "POST":
		if !environmentJSONContentType(r) {
			apiError(w, 415, "JSON_CONTENT_TYPE_REQUIRED")
			return
		}
		var input struct {
			Action string `json:"action"`
		}
		b, e := readEnvironmentObject(r, 1024, "action")
		if e != nil || json.Unmarshal(b, &input) != nil {
			apiError(w, 400, "ACTION_INVALID")
			return
		}
		if input.Action != "inventory" && input.Action != "probe" && input.Action != "launch" {
			apiError(w, 400, "ACTION_NOT_SUPPORTED")
			return
		}
		if e := s.startAction(input.Action); e != nil {
			apiError(w, 409, safeEnvironmentCode(e))
			return
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "STARTED", "action": input.Action})
	case r.URL.Path == "/api/stop" && r.Method == "POST":
		// The stop body is optional, but if supplied it must be one bounded empty
		// object. Closing admission is synchronous, before Shutdown runs elsewhere.
		if r.Body != nil {
			b, e := io.ReadAll(io.LimitReader(r.Body, 1025))
			if e != nil || len(b) > 1024 {
				apiError(w, 400, "STOP_BODY_INVALID")
				return
			}
			if len(strings.TrimSpace(string(b))) != 0 {
				v, e := parseObject(b)
				if e != nil || len(v) != 0 {
					apiError(w, 400, "STOP_BODY_INVALID")
					return
				}
			}
		}
		s.markClosing()
		if s.shutdown != nil {
			go s.shutdown()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "WORKBENCH_STOPPING_OFFICIAL_CLIENT_UNCHANGED"})
	default:
		apiError(w, 405, "METHOD_OR_PATH_NOT_SUPPORTED")
	}
}
func (s *environmentServer) startAction(action string) error {
	if action != "inventory" && action != "probe" && action != "launch" {
		return errors.New("ACTION_NOT_SUPPORTED")
	}
	s.mu.Lock()
	if s.closing || s.ctx.Err() != nil {
		s.mu.Unlock()
		return errors.New("WORKBENCH_IS_STOPPING")
	}
	if s.busy {
		s.mu.Unlock()
		return errors.New("OPERATION_ALREADY_RUNNING")
	}
	var cfg EnvironmentSettings
	if action != "inventory" {
		if s.settings == nil {
			s.mu.Unlock()
			return errors.New("APPROVED_CONFIGURATION_REQUIRED")
		}
		cfg = *s.settings
		if action == "launch" && !cfg.HostAssessmentConfirmed {
			s.mu.Unlock()
			return errors.New("COMPLETE_STAGE_ONE_ASSESSMENT_FIRST")
		}
	}
	if e := appendEnvironmentEvent(s.root, strings.ToUpper(action), "REQUESTED"); e != nil {
		s.mu.Unlock()
		return e
	}
	s.busy = true
	s.operation = action
	s.lastCode = "RUNNING"
	s.workers.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 65*time.Second)
		defer cancel()
		var e error
		var inv *EnvironmentInventory
		var probe *ProxyObservation
		if action == "inventory" || action == "launch" {
			var i EnvironmentInventory
			i, e = s.ops.inventory(ctx)
			if e == nil {
				inv = &i
			}
		}
		if e == nil && (action == "probe" || action == "launch") {
			var p ProxyObservation
			p, e = s.ops.probe(ctx, cfg)
			if e == nil {
				probe = &p
			}
			if e == nil && action == "launch" && !p.Matched {
				e = errors.New("PROXY_HEALTH_NOT_ACCEPTED_NO_CLIENT_LAUNCH")
			}
		}
		if e == nil && action == "launch" {
			if ctx.Err() != nil {
				e = errors.New("WORKBENCH_OPERATION_CANCELLED")
			} else if inv == nil || !inv.Client.Installed || !inv.Client.Verified {
				e = errors.New("VERIFIED_OFFICIAL_CLIENT_REQUIRED")
			} else if inv.TimeZone != cfg.TimeZone {
				e = errors.New("TIME_ZONE_DIFFERENCE_REQUIRES_REVIEW_NO_SETTINGS_CHANGED")
			} else {
				e = s.ops.launch(ctx, inv.Client)
			}
		}
		code := safeEnvironmentCode(e)
		if e == nil {
			switch action {
			case "inventory":
				code = "INVENTORY_COMPLETED_NO_ACCOUNT_READ"
			case "probe":
				code = probe.Status
			case "launch":
				code = "OFFICIAL_ACTIVATION_REQUESTED_ACCOUNT_TEST_PENDING"
			}
		}
		s.mu.Lock()
		if inv != nil {
			s.inventory = inv
		}
		if probe != nil {
			s.probe = probe
		}
		s.lastCode = code
		s.busy = false
		s.operation = ""
		if appendEnvironmentEvent(s.root, strings.ToUpper(action), code) != nil {
			s.lastCode = "ACTION_COMPLETED_AUDIT_REVIEW_REQUIRED"
		}
		s.mu.Unlock()
	}()
	return nil
}
func reuseEnvironmentWorkbench(root string, noBrowser bool) (bool, error) {
	p := filepath.Join(root, "workbench-address.sealed")
	b, e := readSmall(p)
	if e != nil {
		return false, nil
	}
	b, e = platformOpen(b, root)
	if e != nil {
		return false, nil
	}
	var a workbenchAddress
	if json.Unmarshal(b, &a) != nil || !environmentProcessAlive(a.PID) {
		return false, nil
	}
	u, e := url.Parse(a.BaseURL)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false, errors.New("ACTIVE_WORKBENCH_ADDRESS_INVALID")
	}
	// Parse independently; no ambient proxy and no redirects may be used for local reuse.
	addr := strings.TrimPrefix(a.BaseURL, "http://")
	if _, _, e = net.SplitHostPort(addr); e != nil {
		return false, errors.New("ACTIVE_WORKBENCH_ADDRESS_INVALID")
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("REDIRECT_NOT_ALLOWED") }}
	req, _ := http.NewRequest("GET", a.BaseURL+"/api/ping", nil)
	req.Header.Set("Authorization", "Bearer "+a.Token)
	resp, e := client.Do(req)
	if e != nil {
		return false, nil
	}
	defer resp.Body.Close()
	var v struct {
		Instance string `json:"instance"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) != nil || v.Instance != a.Instance {
		return false, nil
	}
	if !noBrowser {
		if e = openEnvironmentBrowser(a.BaseURL + "/#" + a.Token); e != nil {
			return false, e
		}
	}
	return true, nil
}
func serveEnvironment(root string, noBrowser bool, duration time.Duration) error {
	if active, e := reuseEnvironmentWorkbench(root, noBrowser); e != nil {
		return e
	} else if active {
		return nil
	}
	release, e := acquireEnvironmentLock(root, "workbench-active.lock")
	if e != nil {
		return e
	}
	defer release()
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return errors.New("LOOPBACK_WORKBENCH_LISTENER_UNAVAILABLE")
	}
	defer listener.Close()
	base := "http://" + listener.Addr().String()
	token := randomName() + randomName()
	s := newEnvironmentServer(root, base, token, environmentOperations{inventory: inventoryEnvironment, probe: probeEnvironmentProxy, launch: launchOfficialClient})
	defer func() {
		s.markClosing()
		done := make(chan struct{})
		go func() { s.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	server := &http.Server{Handler: s, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	s.shutdown = func() {
		s.markClosing()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	a := workbenchAddress{PID: os.Getpid(), BaseURL: base, Token: token, Instance: s.instance}
	b, _ := json.Marshal(a)
	sealed, e := platformSeal(b, root)
	if e != nil {
		return e
	}
	if e = atomicReplace(filepath.Join(root, "workbench-address.sealed"), sealed); e != nil {
		return e
	}
	_ = appendEnvironmentEvent(root, "WORKBENCH", "STARTED_LOOPBACK_ONLY")
	if !noBrowser {
		go func() { time.Sleep(150 * time.Millisecond); _ = openEnvironmentBrowser(base + "/#" + token) }()
	}
	if e = s.startAction("inventory"); e != nil {
		s.mu.Lock()
		s.lastCode = safeEnvironmentCode(e)
		s.mu.Unlock()
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				installed := s.inventory != nil && s.inventory.Client.Installed && s.inventory.Client.Verified
				busy := s.busy
				s.mu.Unlock()
				if !installed && !busy {
					_ = s.startAction("inventory")
				}
			}
		}
	}()
	timer := time.AfterFunc(duration, s.shutdown)
	defer timer.Stop()
	e = server.Serve(listener)
	if e != nil && e != http.ErrServerClosed {
		return errors.New("WORKBENCH_SERVER_STOPPED")
	}
	_ = appendEnvironmentEvent(root, "WORKBENCH", "STOPPED_NETWORK_AND_CLIENT_UNCHANGED")
	return nil
}
