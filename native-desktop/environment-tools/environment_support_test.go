package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironmentSupportReportDoesNotExportIdentifyingState(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	if e := saveEnvironmentSettings(root, fixtureSettings()); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 45; i++ {
		if e := appendEnvironmentEvent(root, "INVENTORY", "INVENTORY_COMPLETED_NO_ACCOUNT_READ"); e != nil {
			t.Fatal(e)
		}
	}
	fake := func(context.Context) (EnvironmentInventory, error) {
		return EnvironmentInventory{TimeZone: fixtureSettings().TimeZone, Client: OfficialClient{Installed: true, Verified: true, Version: "6.12345.2.0", Path: canary, ProfilePath: canary, ApplicationID: canary}}, nil
	}
	r, e := environmentSupportReport(context.Background(), root, fake)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	for _, forbidden := range []string{canary, root, fixtureSettings().ExpectedExit, fixtureSettings().ProxyURL, fixtureSettings().TimeZone, "runtime-", "environment-settings.sealed"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("identifying local state was exported")
		}
	}
	if !r["installedRuntimeMatchesReceipt"].(bool) || !r["settingsReadable"].(bool) || !r["timeZoneMatchesOrder"].(bool) || r["officialClientVersion"] != "6.12345.2.0" || len(r["events"].([]environmentSupportEvent)) != 40 {
		t.Fatal("support report lost relevant nonidentifying state")
	}
	if _, e = environmentSupportReport(context.Background(), filepath.Dir(root), fake); e == nil {
		t.Fatal("unowned directory was inspected")
	}
}

func TestEnvironmentSupportEndpointIsAuthenticatedAndDoesNotLaunchHelpers(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	s := newEnvironmentServer(root, "http://127.0.0.1:1", "support-fixture-token", environmentOperations{inventory: func(context.Context) (EnvironmentInventory, error) {
		t.Error("support must reuse cached inventory")
		return EnvironmentInventory{}, nil
	}})
	defer s.cancel()
	s.inventory = &EnvironmentInventory{Client: OfficialClient{Installed: true, Verified: true, Version: canary, Path: canary}}
	request := func(auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, s.baseURL+"/api/support", nil)
		if auth {
			r.Header.Set("Authorization", "Bearer "+s.token)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if request(false).Code != 401 {
		t.Fatal("unauthenticated report was exported")
	}
	w := request(true)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "HONGAI-Support.json") || bytes.Contains(w.Body.Bytes(), []byte(canary)) || bytes.Contains(w.Body.Bytes(), []byte(s.token)) {
		t.Fatal("support response authentication or privacy failed")
	}
	export := func(origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, s.baseURL+"/api/support/export", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+s.token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if export("https://other.example", "{}").Code != 403 || export(s.baseURL, `{"path":"elsewhere"}`).Code != 400 {
		t.Fatal("native export accepted a cross-origin or caller-chosen destination")
	}
	if _, e := os.Stat(filepath.Join(root, "diagnostics")); !os.IsNotExist(e) {
		t.Fatal("rejected export created state")
	}
	var result struct {
		FilePath string `json:"filePath"`
	}
	w = export(s.baseURL, "{}")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || filepath.Dir(result.FilePath) != filepath.Join(root, "diagnostics") {
		t.Fatal("native support file was not saved inside its owned directory")
	}
	contents, e := os.ReadFile(result.FilePath)
	if e != nil || bytes.Contains(contents, []byte(canary)) || bytes.Contains(contents, []byte(root)) || bytes.Contains(contents, []byte(s.token)) {
		t.Fatal("native support file violated the selected-field export boundary")
	}
	s.markClosing()
	if request(true).Code != 409 {
		t.Fatal("support request accepted during shutdown")
	}
}

func TestEnvironmentSupportOmitsCorruptAndUnboundedEventText(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	line := `{"event":{"utc":"not a timestamp","kind":"` + canary + `","code":"READY"},"hash":"0000000000000000000000000000000000000000000000000000000000000000"}`
	p := filepath.Join(root, "environment-events.jsonl")
	if e := os.WriteFile(p, []byte(strings.Repeat(canary, 10000)+"\n"+line+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	events, status := environmentSupportEvents(root)
	if len(events) != 0 || status != "INVALID_EVENT_RECORDS_OMITTED" {
		t.Fatal("unsafe event tail was exported")
	}
	if environmentVersionStringSafe(canary) || environmentVersionStringSafe("192.168.1.1") || environmentVersionStringSafe("12345678901") || !environmentVersionStringSafe("6.12345.2.0") {
		t.Fatal("free-form client text passed the version filter")
	}
}

func TestEnvironmentSupportRedactsUppercaseIdentifiersAndNormalizesUTC(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	secret := strings.ToUpper(canary)
	event, _ := json.Marshal(map[string]string{"utc": "2026-11-27T20:00:00+08:00", "kind": secret, "code": secret})
	record, _ := json.Marshal(map[string]any{"event": json.RawMessage(event), "hash": digest(event)})
	if e := os.WriteFile(filepath.Join(root, "environment-events.jsonl"), append(record, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	events, _ := environmentSupportEvents(root)
	b, _ := json.Marshal(events)
	if len(events) != 1 || events[0].UTC != "2026-11-27T12:00:00Z" || bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte("+08:00")) {
		t.Fatal("support exported arbitrary identifiers or source time-zone metadata")
	}
}
