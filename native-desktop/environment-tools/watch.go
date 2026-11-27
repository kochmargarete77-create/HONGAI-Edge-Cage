package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type observedFile struct {
	size                  int64
	modified, stableSince time.Time
	attempts              int
}

// Observe one explicitly approved directory. This never launches an installer,
// changes network configuration or marks first-launch protection accepted.
func watchCandidates(ctx context.Context, directory, source string, interval, stability time.Duration, verify func(string, string) (map[string]any, error)) (map[string]any, error) {
	directory, e := realPath(directory, true)
	if e != nil {
		return nil, e
	}
	started := time.Now()
	observed := map[string]observedFile{}
	initialEntries, e := os.ReadDir(directory)
	if e != nil {
		return nil, errors.New("APPROVED_DOWNLOAD_DIRECTORY_UNREADABLE")
	}
	initial := map[string]bool{}
	for _, entry := range initialEntries {
		initial[entry.Name()] = true
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("DOWNLOAD_OBSERVATION_ENDED_NO_VERIFIED_CANDIDATE")
		case now := <-ticker.C:
			entries, e := os.ReadDir(directory)
			if e != nil {
				return nil, errors.New("APPROVED_DOWNLOAD_DIRECTORY_UNREADABLE")
			}
			if len(entries) > 4096 {
				return nil, errors.New("DOWNLOAD_DIRECTORY_SCAN_LIMIT")
			}
			for _, entry := range entries {
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				supported := ext == ".exe" || ext == ".msix"
				if runtime.GOOS == "darwin" {
					supported = ext == ".pkg" || ext == ".app"
				}
				if !supported || entry.Type()&os.ModeSymlink != 0 {
					continue
				}
				info, e := entry.Info()
				if e != nil || (initial[entry.Name()] && info.ModTime().Before(started.Add(-5*time.Second))) {
					continue
				}
				file := filepath.Join(directory, entry.Name())
				prior, exists := observed[file]
				if !exists || prior.size != info.Size() || !prior.modified.Equal(info.ModTime()) {
					if len(observed) >= 32 {
						return nil, errors.New("TOO_MANY_SIMULTANEOUS_DOWNLOAD_CANDIDATES")
					}
					observed[file] = observedFile{size: info.Size(), modified: info.ModTime(), stableSince: now}
					continue
				}
				if now.Sub(prior.stableSince) < stability || prior.attempts >= 3 {
					continue
				}
				prior.attempts++
				observed[file] = prior
				result, e := verify(file, source)
				if e != nil {
					continue
				}
				result["downloadObservation"] = "NEW_STABLE_CANDIDATE_IN_APPROVED_DIRECTORY"
				result["automaticInstallerExecution"] = false
				result["actualClientAttachmentAccepted"] = false
				return result, nil
			}
		}
	}
}
