package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func environmentSecurityRequest(s *environmentServer, route, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", s.baseURL+route, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Origin", s.baseURL)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestEnvironmentStrictActionBodiesRejectAmbiguityAndOversizedPrefixes(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	var inventoryCalls atomic.Int32
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture-token", environmentOperations{
		inventory: func(context.Context) (EnvironmentInventory, error) {
			inventoryCalls.Add(1)
			return EnvironmentInventory{}, nil
		},
	})
	defer s.cancel()
	for _, body := range []string{
		`{"action":"inventory","action":"launch"}`,
		`{"Action":"inventory"}`,
		`{"action":"inventory"}{"action":"launch"}`,
		`{"action":"inventory"} trailing-data`,
		`null`,
		`{"action":"inventory"}` + strings.Repeat(" ", 1025),
	} {
		if response := environmentSecurityRequest(s, "/api/action", body); response.Code != 400 {
			t.Fatalf("ambiguous or oversized body accepted with status %d", response.Code)
		}
	}
	if inventoryCalls.Load() != 0 {
		t.Fatal("an invalid request ran an operation")
	}
	if response := environmentSecurityRequest(s, "/api/action", `{"action":"inventory"}`); response.Code != 202 {
		t.Fatalf("canonical UTF-8 JSON rejected with status %d", response.Code)
	}
	waitEnvironmentAction(t, s)
	if inventoryCalls.Load() != 1 {
		t.Fatal("canonical request did not run exactly once")
	}
}

func TestEnvironmentStopSynchronouslyClosesAdmissionAndCancelsPendingLaunch(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	probeStarted := make(chan struct{})
	probeReleased := make(chan struct{})
	var launches atomic.Int32
	ops := mockEnvironmentOperations(&launches, true)
	ops.probe = func(context.Context, EnvironmentSettings) (ProxyObservation, error) {
		close(probeStarted)
		<-probeReleased
		// Deliberately ignore cancellation to verify the orchestration gate too.
		return ProxyObservation{Status: "FIXTURE_PROBE", Matched: true, Samples: 3}, nil
	}
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture-token", ops)
	defer s.cancel()
	cfg := fixtureSettings()
	s.settings = &cfg
	if e := s.startAction("launch"); e != nil {
		t.Fatal(e)
	}
	<-probeStarted
	if response := environmentSecurityRequest(s, "/api/stop", `{}`); response.Code != 200 {
		t.Fatal("stop request rejected")
	}
	if s.ctx.Err() == nil {
		t.Fatal("stop response returned before cancelling the local work context")
	}
	if e := s.startAction("inventory"); e == nil {
		t.Fatal("operation accepted after stop")
	}
	close(probeReleased)
	waitEnvironmentAction(t, s)
	s.workers.Wait()
	if launches.Load() != 0 {
		t.Fatal("cancelled pending launch still activated a client")
	}
}

func TestEnvironmentCorruptAuditBlocksLaunchAndConfigurationCommit(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	if e := os.WriteFile(filepath.Join(root, "environment-events.jsonl"), []byte("CORRUPT_RECORD\n"), 0600); e != nil {
		t.Fatal(e)
	}
	var launches atomic.Int32
	s := newEnvironmentServer(root, "http://127.0.0.1:19001", "fixture-token", mockEnvironmentOperations(&launches, true))
	defer s.cancel()
	cfg := fixtureSettings()
	s.settings = &cfg
	if e := s.startAction("launch"); e == nil {
		t.Fatal("launch accepted with a corrupt audit tail")
	}
	b, _ := json.Marshal(cfg)
	if response := environmentSecurityRequest(s, "/api/settings", string(b)); response.Code != 409 {
		t.Fatalf("configuration commit accepted without an intact audit log: %d", response.Code)
	}
	if _, e := os.Stat(filepath.Join(root, "environment-settings.sealed")); !os.IsNotExist(e) {
		t.Fatal("configuration was persisted after audit rejection")
	}
	if launches.Load() != 0 {
		t.Fatal("a client was launched despite corrupt audit evidence")
	}
}

func TestEnvironmentConcurrentOperationalEventsHaveOneHashChain(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	var workers sync.WaitGroup
	failures := make(chan error, 12)
	for n := 0; n < 12; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for k := 0; k < 6; k++ {
				if e := appendEnvironmentEvent(root, "FIXTURE", "CONCURRENT_EVENT"); e != nil {
					failures <- e
					return
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, "environment-events.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	if len(lines) != 72 {
		t.Fatal("concurrent event records were lost")
	}
	previous := ""
	for _, line := range lines {
		var record struct {
			Event json.RawMessage `json:"event"`
			Hash  string          `json:"hash"`
		}
		if json.Unmarshal(line, &record) != nil || digest(record.Event) != record.Hash {
			t.Fatal("event hash invalid")
		}
		var event struct {
			PreviousHash string `json:"previousHash"`
		}
		if json.Unmarshal(record.Event, &event) != nil || event.PreviousHash != previous {
			t.Fatal("event chain forked during concurrent append")
		}
		previous = record.Hash
	}
	if appendEnvironmentEvent(root, "FIXTURE", "raw token = "+canary) == nil {
		t.Fatal("raw message accepted as a symbolic audit code")
	}
}

func TestEnvironmentConcurrentLeaseTransitionsDoNotAdmitTwoOwners(t *testing.T) {
	root, _ := fixtureEnvironment(t)
	var workers sync.WaitGroup
	var active atomic.Int32
	var overlap atomic.Bool
	var admitted atomic.Int32
	start := make(chan struct{})
	for n := 0; n < 12; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			release, e := acquireEnvironmentLock(root, "environment-install.lock")
			if e != nil {
				return
			}
			admitted.Add(1)
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
			release()
		}()
	}
	close(start)
	workers.Wait()
	if admitted.Load() == 0 || overlap.Load() {
		t.Fatal("lease ownership was absent or overlapped")
	}
	// Holding an active lease must not hold the OS transition guard, otherwise
	// independent audit/other lease transitions would deadlock for its lifetime.
	release, e := acquireEnvironmentLock(root, "workbench-active.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	other, e := acquireEnvironmentLock(root, "environment-events.lock")
	if e != nil {
		t.Fatal("a long-lived lease monopolized the transition guard")
	}
	other()
}
