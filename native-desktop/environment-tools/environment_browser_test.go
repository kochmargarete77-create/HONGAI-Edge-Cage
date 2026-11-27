package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvironmentBrowserConfigurationAndDailyEntryFlow(t *testing.T) {
	if os.Getenv("HONGAI_BROWSER_FIXTURE_PATH") == "" {
		t.Skip("BROWSER_UI_FIXTURE_REQUIRED_IN_CI_LOCAL_LOW_MEMORY_EXCLUDED")
	}
	root, _ := fixtureEnvironment(t)
	var launches atomic.Int32
	s := newEnvironmentServer(root, "http://127.0.0.1:1", "ui-synthetic-session", mockEnvironmentOperations(&launches, true))
	defer s.cancel()
	server := httptest.NewServer(s)
	defer server.Close()
	s.baseURL = server.URL
	if e := s.startAction("inventory"); e != nil {
		t.Fatal(e)
	}
	waitEnvironmentAction(t, s)
	outDir := testDirectory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "node", "environment_ui_smoke.cjs")
	c.Env = append(os.Environ(), "HONGAI_UI_TEST_URL="+server.URL+"/#"+s.token, "HONGAI_UI_TEST_OUTPUT="+outDir)
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("browser UI fixture failed: %v %s", e, out)
	}
	if launches.Load() != 1 {
		t.Fatal("UI did not perform exactly one synthetic launch")
	}
	s.mu.Lock()
	saved := s.settings != nil && s.settings.ExpectedExit == fixtureSettings().ExpectedExit
	s.mu.Unlock()
	if !saved {
		t.Fatal("UI settings did not persist correctly")
	}
	if dir := os.Getenv("HONGAI_UI_ARTIFACT_DIR"); dir != "" {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"ui-desktop.png", "ui-narrow.png", "ui-smoke-result.json"} {
			b, e := os.ReadFile(filepath.Join(outDir, name))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
}
