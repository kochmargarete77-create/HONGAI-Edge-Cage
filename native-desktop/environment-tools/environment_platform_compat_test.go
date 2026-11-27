//go:build windows || darwin

package main

import (
	"strings"
	"testing"
)

func TestEnvironmentBrowserAddressAcceptsOnlyLocalSession(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, p := range []string{"http://127.0.0.1:17896/#" + token, "http://127.0.0.1:17896#" + token} {
		if !validEnvironmentBrowserAddress(p) {
			t.Fatal("valid loopback session rejected")
		}
	}
	for _, p := range []string{"https://127.0.0.1:17896/#" + token, "http://localhost:17896/#" + token, "http://example.invalid:17896/#" + token, "http://127.0.0.1:0/#" + token, "http://127.0.0.1:17896/admin#" + token, "http://user@127.0.0.1:17896/#" + token, "http://127.0.0.1:17896/?x=1#" + token, "file:///tmp/readme", "http://127.0.0.1:17896/#short"} {
		if validEnvironmentBrowserAddress(p) {
			t.Fatal("unsupported browser destination accepted")
		}
	}
}
