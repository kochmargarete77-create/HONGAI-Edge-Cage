package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func scopedPolicy(paths ...string) Policy {
	return Policy{Version: 2, Rules: []Rule{{ID: "network", Value: hostIP, Encodings: []string{"url", "base64"}, Paths: paths}}}
}

func scopedMessage(t *testing.T, filter *Filter, value any, stats *Counts) map[string]any {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	out, e := filter.message(b, stats)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := strictJSON(out)
	if e != nil {
		t.Fatal(e)
	}
	return parsed.(map[string]any)
}

func TestScopedPrivacyPreservesOtherBusinessUsesAndProtocol(t *testing.T) {
	filter, e := newFilter(scopedPolicy("/result/structuredContent/network/exit"))
	if e != nil {
		t.Fatal(e)
	}
	input := map[string]any{"jsonrpc": "2.0", "id": json.Number("9007199254740993123456"), "result": map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "business invoice reference " + hostIP}},
		"structuredContent": map[string]any{
			"network": map[string]any{"exit": hostIP, "enabled": true, "port": json.Number("443"), "empty": nil},
			"invoice": map[string]any{"reference": hostIP, "code": "const endpoint = '" + hostIP + "';"},
		},
		"tools": []any{map[string]any{"name": hostIP, "inputSchema": map[string]any{"description": hostIP}}},
	}}
	var stats Counts
	got := scopedMessage(t, filter, input, &stats)
	expected := input["result"].(map[string]any)["structuredContent"].(map[string]any)["network"].(map[string]any)
	expected["exit"] = "[HONGAI:network]"
	if !reflect.DeepEqual(got, input) {
		t.Fatal("scope filter changed unrelated business, schema, routing or JSON value types")
	}
	if stats.Replacements != 1 || stats.ScopedPathsMatched != 1 || stats.ScopedPathChecks != 1 || stats.ConfiguredPaths != 1 || stats.PolicyVersion != 2 || stats.Coverage != "EXACT_JSON_POINTER_STRING_VALUES_ONLY" {
		t.Fatal("scope coverage was not explicit", stats)
	}
	errorFilter, _ := newFilter(scopedPolicy("/error/message"))
	errorInput := map[string]any{"jsonrpc": "2.0", "id": hostIP, "error": map[string]any{"code": json.Number("-32000"), "message": "diagnostic " + hostIP, "data": map[string]any{"business": hostIP}}}
	got = scopedMessage(t, errorFilter, errorInput, &Counts{})
	if got["id"] != hostIP || got["error"].(map[string]any)["data"].(map[string]any)["business"] != hostIP || got["error"].(map[string]any)["message"] != "diagnostic [HONGAI:network]" {
		t.Fatal("error field scope changed unrelated protocol or error business data")
	}
}

func TestScopedPrivacyRFC6901EscapesAndCoverageGaps(t *testing.T) {
	filter, e := newFilter(scopedPolicy(
		"/result/structuredContent/a~1b/~0host", "/result/structuredContent//value",
		"/result/absent", "/result/structuredContent", "/result/content/0/data", "/result/content/01/text"))
	if e != nil {
		t.Fatal(e)
	}
	input := map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
		"structuredContent": map[string]any{"a/b": map[string]any{"~host": hostIP}, "": map[string]any{"value": hostIP}},
		"content":           []any{map[string]any{"type": "image", "mimeType": "image/png", "data": hostIP, "text": hostIP}},
	}}
	var stats Counts
	got := scopedMessage(t, filter, input, &stats)
	result := got["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if structured["a/b"].(map[string]any)["~host"] != "[HONGAI:network]" || structured[""].(map[string]any)["value"] != "[HONGAI:network]" {
		t.Fatal("escaped pointer keys or exact empty object key did not resolve")
	}
	if !reflect.DeepEqual(result["content"], input["result"].(map[string]any)["content"]) || stats.ScopedPathChecks != 6 || stats.ScopedPathsMatched != 2 || stats.ScopedPathsMissing != 2 || stats.ScopedPathsNonString != 1 || stats.ScopedPathsProtected != 1 || stats.UninspectedBinaryBlocks != 1 || stats.Replacements != 2 {
		t.Fatal("binary, missing, non-string or invalid array index coverage was overstated", stats)
	}
}

func TestScopedPrivacyRejectsUnsafePathsAndLabelCollisions(t *testing.T) {
	badPaths := []string{"", "result/content/0/text", "/params/message", "/jsonrpc", "/id", "/method", "/result/inputSchema/description", "/result/outputSchema/title", "/result/uri", "/result/progressToken", "/result/nextCursor", "/result/blob", "/result/binary", "/result/name", "/result/type", "/result/mimeType", "/result/protocolVersion", "/result/escaped~2key", "/result/invalid~", "/result/content/*/text", "/result/**", "/result/id/text"}
	for _, path := range badPaths {
		if _, e := newFilter(scopedPolicy(path)); e == nil {
			t.Fatal("unsafe or ambiguous selector accepted")
		}
	}
	for _, p := range []Policy{
		{Version: 2, Rules: []Rule{{ID: "network", Value: hostIP}}},
		{Version: 2, Rules: []Rule{{ID: "network", Value: hostIP, Paths: []string{"/result/text", "/result/text"}}}},
		{Version: 1, Rules: []Rule{{ID: "network", Value: hostIP, Paths: []string{"/result/text"}}}},
		{Version: 2, Rules: []Rule{{ID: "SensitiveSecret8", Value: "SensitiveSecret8", Paths: []string{"/result/text"}}}},
		{Version: 2, Rules: []Rule{{ID: "first", Value: hostIP, Paths: []string{"/result/text"}}, {ID: "second", Value: hostIP, Paths: []string{"/result/text"}}}},
	} {
		if _, e := newFilter(p); e == nil {
			t.Fatal("unsafe version, missing scope, repeated scope or replacement label collision accepted")
		}
	}
	// Identical literals in disjoint paths have independent labels, without
	// forcing a blanket replacement across unrelated fields.
	disjoint := Policy{Version: 2, Rules: []Rule{{ID: "first", Value: hostIP, Paths: []string{"/result/first"}}, {ID: "second", Value: hostIP, Paths: []string{"/result/second"}}}}
	if _, e := newFilter(disjoint); e != nil {
		t.Fatal("unambiguous disjoint path policies were rejected", e)
	}
}

func TestScopedPrivacySelectedEmbeddedJSONAndUntrustedLabels(t *testing.T) {
	policy := Policy{Version: 2, Rules: []Rule{{ID: "privacy", Value: "SensitiveSecret8", Paths: []string{"/result/content/0/text"}}}}
	filter, e := newFilter(policy)
	if e != nil {
		t.Fatal(e)
	}
	inputText := "[HONGAI:SensitiveSecret8] [HONGAI:privacy] SensitiveSecret8"
	got := scopedMessage(t, filter, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": inputText}}}}, &Counts{})
	text := got["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if strings.Contains(text, "SensitiveSecret8") || !strings.Contains(text, "[HONGAI:privacy]") {
		t.Fatal("input masquerading as a label bypassed replacement, or valid output label changed")
	}
	inner := ` { "uri" : "SensitiveSecret8", "id":"SensitiveSecret8", "note":"Sensitive\u0053ecret8", "unchanged":true } `
	var stats Counts
	got = scopedMessage(t, filter, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": inner}}}}, &stats)
	encoded := got["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var decoded map[string]any
	if json.Unmarshal([]byte(encoded), &decoded) != nil || decoded["note"] != "[HONGAI:privacy]" || decoded["uri"] != "SensitiveSecret8" || decoded["id"] != "SensitiveSecret8" || decoded["unchanged"] != true || stats.ScopedEmbeddedFieldsProtected != 2 {
		t.Fatal("selected embedded JSON changed routing fields or hid its uninspected protected fields", stats)
	}
	protectedOnly := " { \"uri\" : \"SensitiveSecret8\" } "
	stats = Counts{}
	got = scopedMessage(t, filter, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": protectedOnly}}}}, &stats)
	if got["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != protectedOnly || stats.Replacements != 0 || stats.ScopedEmbeddedFieldsProtected != 1 {
		t.Fatal("protected-only JSON text was reformatted or raw fallback altered its URI")
	}
	stats = Counts{}
	scopedMessage(t, filter, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "{broken JSON SensitiveSecret8"}}}}, &stats)
	if stats.ScopedEmbeddedJSONUnparsed != 1 {
		t.Fatal("unparsed JSON-like text was claimed as fully understood")
	}
}

func TestScopedPrivacyOutputBudgetRejectsExpansionInBothVersions(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, embedded := range []bool{false, true} {
			rule := Rule{ID: strings.Repeat("L", 32), Value: "12345678"}
			if version == 2 {
				rule.Paths = []string{"/result/text"}
			}
			filter, e := newFilter(Policy{Version: version, Rules: []Rule{rule}})
			if e != nil {
				t.Fatal(e)
			}
			text := strings.Repeat(rule.Value, maximumFrame/16)
			if embedded {
				// Many individually small strings can expand the embedded JSON
				// past the frame limit before it becomes an outer string.
				text = "[" + strings.TrimSuffix(strings.Repeat(`"12345678",`, maximumFrame/32), ",") + "]"
			}
			input, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"text": text}})
			if len(input) >= maximumFrame {
				t.Fatal("expansion fixture itself exceeds input limit")
			}
			var stats Counts
			out, e := filter.message(input, &stats)
			if e == nil || e.Error() != "FILTERED_OUTPUT_FRAME_LIMIT" || out != nil || stats.OutputLimitFailures != 1 {
				t.Fatal("expanded output was forwarded or leaked through a failure payload", version, embedded, stats)
			}
		}
	}
	for _, value := range []any{nil, true, false, json.Number("9007199254740993123456"), "<&>\n\"\\\u2028中文", []any{"ok", json.Number("1.25")}, map[string]any{"escaped\nkey": "\u2029"}} {
		encoded, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		budget := int64(len(encoded))
		if !privacyJSONFits(value, &budget) || budget != 0 {
			t.Fatal("preflight byte accounting differs from encoding/json")
		}
		budget = int64(len(encoded) - 1)
		if privacyJSONFits(value, &budget) {
			t.Fatal("preflight budget admitted an oversized encoding")
		}
	}
}

func TestScopedPrivacyBridgeRealSubprocessPreservesClientFileContent(t *testing.T) {
	root := testDirectory(t)
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	policy := scopedPolicy("/result/content/0/text", "/result/missing")
	policy.Rules = append(policy.Rules, Rule{ID: "secret", Value: canary, Paths: []string{"/result/content/0/text"}})
	binding := Binding{Version: 1, Program: self, Args: []string{"-test.run=TestNativeUpstream", "--"}, Env: map[string]string{"HONGAI_UPSTREAM_FIXTURE": "1", "HONGAI_FIXTURE_ROOT": root, "UPSTREAM_SECRET": canary}, Policy: policy}
	business := "const endpoint = '" + hostIP + "'; business-file-is-not-a-scope"
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"text\":" + strconvQuote(business) + "}}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output bytes.Buffer
	stats, e := runBridge(ctx, binding, strings.NewReader(input), &output)
	if e != nil {
		t.Fatal(e)
	}
	if stats.Messages != 3 || stats.Replacements != 6 || stats.ScopedPathsMatched != 2 || stats.ScopedPathsMissing != 4 || stats.ScopedPathChecks != 6 || stats.ConfiguredPaths != 2 || stats.PolicyVersion != 2 {
		t.Fatal("real bridge path coverage or replacement count differs", stats)
	}
	if bytes.Contains(output.Bytes(), []byte(canary)) || bytes.Contains(output.Bytes(), []byte(hostIP)) || bytes.Contains(output.Bytes(), []byte("MUST_NOT_EXPORT_STDERR")) {
		t.Fatal("selected upstream text or raw stderr escaped the scoped bridge")
	}
	work, e := os.ReadFile(filepath.Join(root, "work.txt"))
	if e != nil || string(work) != business {
		t.Fatal("bridge changed client tool arguments or the underlying business file")
	}
	if !bytes.Contains(output.Bytes(), []byte("business-file-is-not-a-scope")) || !bytes.Contains(output.Bytes(), []byte("Asia/Shanghai")) {
		t.Fatal("unconfigured business or timezone text was altered")
	}
}

func strconvQuote(value string) string {
	b, _ := json.Marshal(value)
	return string(b)
}
