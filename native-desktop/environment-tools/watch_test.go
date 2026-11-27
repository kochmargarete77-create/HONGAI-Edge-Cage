package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestObserverWaitsForStableCandidateAndDoesNotExecute(t *testing.T) {
	root := testDirectory(t)
	extension := ".msix"
	if runtime.GOOS == "darwin" {
		extension = ".pkg"
	}
	file := filepath.Join(root, "candidate"+extension)
	os.WriteFile(file, []byte("in progress"), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	checked := false
	go func() { time.Sleep(30 * time.Millisecond); os.WriteFile(file, []byte("finished bytes"), 0600) }()
	result, e := watchCandidates(ctx, root, "https://claude.ai/download", 10*time.Millisecond, 60*time.Millisecond, func(p, s string) (map[string]any, error) {
		data, _ := os.ReadFile(p)
		if string(data) != "finished bytes" {
			return nil, errors.New("UNFINISHED")
		}
		checked = true
		return map[string]any{"fixtureOnly": true}, nil
	})
	if e != nil || !checked || result["automaticInstallerExecution"] != false || result["actualClientAttachmentAccepted"] != false {
		t.Fatal("OBSERVER_STATE_OR_SCOPE_FAILED", result, e)
	}
}
func TestObserverIgnoresPartialFilesAndStops(t *testing.T) {
	root := testDirectory(t)
	os.WriteFile(filepath.Join(root, "candidate.msix.crdownload"), []byte("partial"), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	calls := 0
	_, e := watchCandidates(ctx, root, "https://claude.ai/download", 10*time.Millisecond, 20*time.Millisecond, func(string, string) (map[string]any, error) { calls++; return nil, nil })
	if e == nil || calls != 0 {
		t.Fatal("PARTIAL_DOWNLOAD_OR_TIMEOUT_HANDLED_INCORRECTLY")
	}
}

func TestObserverFindsNewFileWithPreservedOldTimestamp(t *testing.T) {
	root := testDirectory(t)
	extension := ".msix"
	if runtime.GOOS == "darwin" {
		extension = ".pkg"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		time.Sleep(30 * time.Millisecond)
		file := filepath.Join(root, "new-download"+extension)
		os.WriteFile(file, []byte("complete"), 0600)
		old := time.Unix(100000, 0)
		os.Chtimes(file, old, old)
	}()
	_, e := watchCandidates(ctx, root, "https://claude.ai/download", 10*time.Millisecond, 20*time.Millisecond, func(string, string) (map[string]any, error) { return map[string]any{"fixtureOnly": true}, nil })
	if e != nil {
		t.Fatal("NEW_DOWNLOAD_IGNORED_BECAUSE_TIMESTAMP_WAS_PRESERVED", e)
	}
}
