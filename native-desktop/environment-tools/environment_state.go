package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type environmentOwner struct {
	Schema string `json:"schema"`
	Root   string `json:"root"`
	UserID string `json:"userId"`
}
type environmentLease struct {
	PID        int    `json:"pid"`
	Nonce      string `json:"nonce"`
	CreatedUTC string `json:"createdUtc"`
}

func validEnvironmentOwner(root string) bool {
	var o environmentOwner
	if decodeFile(filepath.Join(root, "environment-owner.json"), &o) != nil {
		return false
	}
	u, e := user.Current()
	return e == nil && o.Schema == "hongai.environment-owner.v1" && samePath(o.Root, root) && o.UserID == u.Uid
}
func saveEnvironmentOwner(root string) error {
	if _, e := os.Lstat(filepath.Join(root, "environment-owner.json")); e == nil {
		if !validEnvironmentOwner(root) {
			return errors.New("ENVIRONMENT_OWNERSHIP_MISMATCH")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return errors.New("ENVIRONMENT_OWNERSHIP_UNREADABLE")
	}
	u, e := user.Current()
	if e != nil {
		return errors.New("CUSTOMER_IDENTITY_UNAVAILABLE")
	}
	b, _ := json.Marshal(environmentOwner{Schema: "hongai.environment-owner.v1", Root: root, UserID: u.Uid})
	return atomicReplace(filepath.Join(root, "environment-owner.json"), b)
}
func acquireEnvironmentLock(root, name string) (func(), error) {
	if name != "environment-install.lock" && name != "workbench-active.lock" && name != "environment-events.lock" {
		return nil, errors.New("LOCK_NAME_NOT_ALLOWED")
	}
	// The OS guard covers only the lease's read/create/remove transition. The
	// longer-lived lease itself must not monopolize the transition guard.
	transitionRelease, e := environmentTransitionGuard(root)
	if e != nil {
		return nil, e
	}
	defer transitionRelease()
	p := filepath.Join(root, name)
	for attempt := 0; attempt < 2; attempt++ {
		lease := environmentLease{PID: os.Getpid(), Nonce: randomName(), CreatedUTC: time.Now().UTC().Format(time.RFC3339)}
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			created, statError := f.Stat()
			b, _ := json.Marshal(lease)
			_, e = f.Write(b)
			if e == nil {
				e = f.Sync()
			}
			closeError := f.Close()
			if e == nil {
				e = closeError
			}
			if e != nil {
				// A failed first write must not strand an undecodable permanent lock.
				// Remove only the same file we just created, never a replacement.
				if now, checkError := os.Lstat(p); statError == nil && checkError == nil && os.SameFile(created, now) {
					_ = os.Remove(p)
				}
				return nil, errors.New("LOCK_WRITE_FAILED")
			}
			return func() {
				releaseTransition, guardError := environmentTransitionGuard(root)
				if guardError != nil {
					// Keep the lease rather than deleting without serialized nonce
					// validation. A later dead-owner recovery can handle it safely.
					return
				}
				defer releaseTransition()
				var now environmentLease
				if decodeFile(p, &now) == nil && now.Nonce == lease.Nonce {
					_ = os.Remove(p)
				}
			}, nil
		}
		if !os.IsExist(e) {
			return nil, errors.New("ENVIRONMENT_LOCK_CREATE_FAILED")
		}
		var old environmentLease
		if decodeFile(p, &old) != nil || old.PID <= 0 || old.Nonce == "" || environmentProcessAlive(old.PID) {
			return nil, errors.New("ENVIRONMENT_OPERATION_ALREADY_RUNNING")
		}
		if !validEnvironmentOwner(root) {
			return nil, errors.New("STALE_LOCK_WITHOUT_OWNERSHIP")
		}
		if e = os.Remove(p); e != nil {
			return nil, errors.New("STALE_OWNED_LOCK_REMOVE_FAILED")
		}
	}
	return nil, errors.New("ENVIRONMENT_LOCK_RETRY_EXHAUSTED")
}

// Serializes this process and also takes a bounded lease for other manager
// processes. This is integrity protection for owned operational logs, not a
// security boundary against software with the same user's filesystem rights.
var environmentEventMutex sync.Mutex

func environmentEventCodeValid(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func environmentLastEventHash(p string) (string, error) {
	info, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil || !info.Mode().IsRegular() {
		return "", errors.New("EVENT_LOG_PATH_INVALID")
	}
	if info.Size() == 0 {
		return "", nil
	}
	f, e := os.Open(p)
	if e != nil {
		return "", errors.New("EVENT_LOG_READ_FAILED")
	}
	defer f.Close()
	start := info.Size() - 8192
	if start < 0 {
		start = 0
	}
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return "", errors.New("EVENT_LOG_SEEK_FAILED")
	}
	tail, e := io.ReadAll(f)
	if e != nil {
		return "", errors.New("EVENT_LOG_READ_FAILED")
	}
	tail = bytes.TrimSpace(tail)
	if i := bytes.LastIndexByte(tail, '\n'); i >= 0 {
		tail = tail[i+1:]
	}
	var last struct {
		Event json.RawMessage `json:"event"`
		Hash  string          `json:"hash"`
	}
	if json.Unmarshal(tail, &last) != nil || len(last.Hash) != 64 || digest(last.Event) != last.Hash {
		return "", errors.New("EVENT_LOG_TAIL_INVALID_REVIEW_REQUIRED")
	}
	return last.Hash, nil
}
func appendEnvironmentEvent(root, kind, code string) error {
	if !environmentEventCodeValid(kind, 64) || !environmentEventCodeValid(code, 100) {
		return errors.New("EVENT_LOG_SYMBOLIC_CODES_ONLY")
	}
	environmentEventMutex.Lock()
	defer environmentEventMutex.Unlock()
	if !validEnvironmentOwner(root) {
		return errors.New("EVENT_LOG_OWNERSHIP_REQUIRED")
	}
	var release func()
	var e error
	for attempts := 0; attempts < 100; attempts++ {
		release, e = acquireEnvironmentLock(root, "environment-events.lock")
		if e == nil {
			break
		}
		if !strings.Contains(e.Error(), "ALREADY_RUNNING") {
			return e
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		return errors.New("EVENT_LOG_BUSY_RETRY_LATER")
	}
	defer release()
	p := filepath.Join(root, "environment-events.jsonl")
	previous, e := environmentLastEventHash(p)
	if e != nil {
		return e
	}
	if previous == "" {
		previous, e = environmentLastEventHash(p + ".1")
		if e != nil {
			return e
		}
	}
	if info, e := os.Stat(p); e == nil && info.Size() > 2<<20 {
		for n := 2; n >= 1; n-- {
			from := p + "." + string(rune('0'+n))
			to := p + "." + string(rune('0'+n+1))
			if _, e = os.Lstat(from); e == nil {
				if e = replaceFile(from, to); e != nil {
					return e
				}
			}
		}
		if e = replaceFile(p, p+".1"); e != nil {
			return e
		}
	}
	event := struct {
		UTC          string `json:"utc"`
		Kind         string `json:"kind"`
		Code         string `json:"code"`
		PreviousHash string `json:"previousHash"`
	}{time.Now().UTC().Format(time.RFC3339Nano), kind, code, previous}
	b, _ := json.Marshal(event)
	line, _ := json.Marshal(struct {
		Event any    `json:"event"`
		Hash  string `json:"hash"`
	}{event, digest(b)})
	f, e := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("EVENT_LOG_APPEND_FAILED")
	}
	if _, e = f.Write(append(line, '\n')); e != nil {
		_ = f.Close()
		return errors.New("EVENT_LOG_WRITE_FAILED")
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return errors.New("EVENT_LOG_SYNC_FAILED")
	}
	if e = f.Close(); e != nil {
		return errors.New("EVENT_LOG_CLOSE_FAILED")
	}
	return nil
}
