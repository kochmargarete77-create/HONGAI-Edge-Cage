package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var ioReadFull = io.ReadFull

func loadBinding(file, root string) (Binding, error) {
	var binding Binding
	root, e := realPath(root, true)
	if e != nil {
		return binding, e
	}
	file, e = realPath(file, false)
	if e != nil {
		return binding, e
	}
	if !strings.HasPrefix(file, root+string(os.PathSeparator)) {
		return binding, errors.New("BINDING_OUTSIDE_APPROVED_DATA_ROOT")
	}
	sealed, e := readSmall(file)
	if e != nil {
		return binding, e
	}
	plain, e := platformOpen(sealed, root)
	if e != nil {
		return binding, e
	}
	if json.Unmarshal(plain, &binding) != nil || binding.Version != 1 || !filepath.IsAbs(binding.Program) {
		return binding, errors.New("SEALED_BINDING_INVALID")
	}
	if _, e = newFilter(binding.Policy); e != nil {
		return binding, e
	}
	return binding, nil
}

func runBridge(ctx context.Context, b Binding, input io.Reader, output io.Writer) (Counts, error) {
	var stats Counts
	f, e := newFilter(b.Policy)
	if e != nil {
		return stats, e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.Program, b.Args...)
	cmd.WaitDelay = 2 * time.Second
	env := map[string]string{}
	for _, entry := range os.Environ() {
		key, val, ok := strings.Cut(entry, "=")
		if ok {
			env[key] = val
		}
	}
	for key, val := range b.Env {
		env[key] = val
	}
	for key, val := range env {
		cmd.Env = append(cmd.Env, key+"="+val)
	}
	childIn, e := cmd.StdinPipe()
	if e != nil {
		return stats, errors.New("UPSTREAM_PIPE_FAILED")
	}
	childOut, e := cmd.StdoutPipe()
	if e != nil {
		return stats, errors.New("UPSTREAM_PIPE_FAILED")
	}
	childErr, e := cmd.StderrPipe()
	if e != nil {
		return stats, errors.New("UPSTREAM_PIPE_FAILED")
	}
	if e = cmd.Start(); e != nil {
		return stats, errors.New("UPSTREAM_START_FAILED")
	}
	done := make(chan struct{})
	defer close(done)
	var invalidInput atomic.Bool
	go func() {
		defer childIn.Close()
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64*1024), maximumFrame+1)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if len(line) > maximumFrame {
				invalidInput.Store(true)
				cancel()
				return
			}
			v, e := strictJSON(line)
			if e != nil {
				invalidInput.Store(true)
				cancel()
				return
			}
			m, ok := v.(map[string]any)
			if !ok || m["jsonrpc"] != "2.0" {
				invalidInput.Store(true)
				cancel()
				return
			}
			if _, e = childIn.Write(append(line, '\n')); e != nil {
				return
			}
		}
		if scanner.Err() != nil {
			invalidInput.Store(true)
			cancel()
		}
		// Client EOF means the client is gone. Give in-flight replies a bounded
		// drain, then stop this owned upstream. No infinite invisible process.
		go func() {
			select {
			case <-time.After(2 * time.Second):
				cancel()
			case <-done:
			}
		}()
	}()
	stderrDone := make(chan struct{})
	go func() { io.Copy(io.Discard, childErr); close(stderrDone) }() // Raw stderr never enters protocol or audit.
	scanner := bufio.NewScanner(childOut)
	scanner.Buffer(make([]byte, 64*1024), maximumFrame+1)
	var failure error
	for scanner.Scan() {
		filtered, e := f.message(scanner.Bytes(), &stats)
		if e != nil {
			failure = e
			cancel()
			break
		}
		if _, e = output.Write(append(filtered, '\n')); e != nil {
			failure = errors.New("CLIENT_OUTPUT_CLOSED")
			cancel()
			break
		}
	}
	if scanner.Err() != nil && failure == nil {
		failure = errors.New("UPSTREAM_FRAME_LIMIT_OR_READ_FAILED")
		cancel()
	}
	waitErr := cmd.Wait()
	<-stderrDone
	if failure != nil {
		return stats, failure
	}
	if invalidInput.Load() {
		return stats, errors.New("CLIENT_INVALID_PROTOCOL")
	}
	if waitErr != nil {
		return stats, errors.New("UPSTREAM_EXITED_UNSUCCESSFULLY")
	}
	return stats, nil
}

func writeAudit(root string, stats Counts, code string) error {
	root, e := realPath(root, true)
	if e != nil {
		return e
	}
	// Small, fixed schema; no messages, tool arguments, upstream stderr or paths.
	a := map[string]any{"schema": "hongai.mcp-privacy-audit.v1", "messages": stats.Messages, "replacements": stats.Replacements, "uninspectedBinaryBlocks": stats.UninspectedBinaryBlocks, "result": code, "rawPayloadsExported": false, "nativeHardwareReadsCovered": false, "arbitraryEncodedDataCovered": false}
	data, _ := json.Marshal(a)
	// Keep at most twenty exact owned audit entries. Do not traverse subtrees.
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "audit-") && strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
	}
	if count >= 20 {
		return nil
	} // Bounded no-delete policy; operator can archive later.
	return writeNew(filepath.Join(root, "audit-"+randomName()+".json"), data)
}

func cleanBOM(data []byte) []byte { return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}) }
