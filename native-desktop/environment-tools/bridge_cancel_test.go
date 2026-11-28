package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type bridgeReadyBuffer struct {
	bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (b *bridgeReadyBuffer) Write(data []byte) (int, error) {
	n, err := b.Buffer.Write(data)
	if bytes.Contains(data, []byte("fixture reply")) {
		b.once.Do(func() { close(b.ready) })
	}
	return n, err
}

// This fixture creates only a known child test executable. A bounded lifetime
// and exact PID cleanup prevent broad process termination during acceptance.
func TestBridgePipeFixture(t *testing.T) {
	switch os.Getenv("HONGAI_PIPE_FIXTURE") {
	case "holder":
		fmt.Fprintln(os.Stderr, "HONGAI_PIPE_HOLDER_PRIVATE_STDERR")
		time.Sleep(6 * time.Second)
		os.Exit(0)
	case "parent":
		self, _ := os.Executable()
		child := exec.Command(self, "-test.run=^TestBridgePipeFixture$")
		child.Env = mergedEnvironment(os.Environ(), map[string]string{"HONGAI_PIPE_FIXTURE": "holder"}, false)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(4)
		}
		if os.WriteFile(filepath.Join(os.Getenv("HONGAI_PIPE_ROOT"), "holder.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0600) != nil {
			os.Exit(5)
		}
		fmt.Fprintln(os.Stdout, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fixture reply"}]}}`)
		os.Exit(0)
	}
}

func TestBridgeCancellationReleasesOwnedPipesWithLiveDescendant(t *testing.T) {
	root := testDirectory(t)
	defer func() {
		data, err := os.ReadFile(filepath.Join(root, "holder.pid"))
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil || pid < 1 {
			return
		}
		if process, err := os.FindProcess(pid); err == nil {
			process.Kill()
			process.Release()
		}
	}()
	self, _ := os.Executable()
	binding := Binding{Version: 1, Program: self, Args: []string{"-test.run=^TestBridgePipeFixture$"}, Env: map[string]string{"HONGAI_PIPE_FIXTURE": "parent", "HONGAI_PIPE_ROOT": root}, Policy: Policy{Version: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &bridgeReadyBuffer{ready: make(chan struct{})}
	completed := make(chan error, 1)
	go func() {
		_, err := runBridge(ctx, binding, strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"), output)
		completed <- err
	}()
	select {
	case <-output.ready:
		data, err := os.ReadFile(filepath.Join(root, "holder.pid"))
		if err != nil {
			cancel()
			t.Fatal("DESCENDANT_FIXTURE_WAS_NOT_STARTED")
		}
		if pid, err := strconv.Atoi(string(data)); err != nil || pid < 1 {
			cancel()
			t.Fatal("DESCENDANT_FIXTURE_PID_INVALID")
		}
	case err := <-completed:
		t.Fatalf("bridge ended before pipe fixture became ready: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		select {
		case <-completed:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("DESCENDANT_FIXTURE_START_TIMEOUT")
	}
	started := time.Now()
	cancel()
	var err error
	select {
	case err = <-completed:
	case <-time.After(4 * time.Second):
		t.Fatal("CANCELLED_BRIDGE_WAITED_FOR_DESCENDANT_PIPE_EOF")
	}
	if err == nil || err.Error() != "BRIDGE_CANCELLED" {
		t.Fatalf("cancellation result must be symbolic: %v", err)
	}
	if time.Since(started) > 4*time.Second {
		t.Fatal("CANCELLED_BRIDGE_WAITED_FOR_DESCENDANT_PIPE_EOF")
	}
	if !bytes.Contains(output.Bytes(), []byte("fixture reply")) {
		t.Fatal("PIPE_FIXTURE_WAS_NOT_EXERCISED")
	}
	if bytes.Contains(output.Bytes(), []byte("HONGAI_PIPE_HOLDER_PRIVATE_STDERR")) {
		t.Fatal("STDERR_ENTERED_PROTOCOL")
	}
}
