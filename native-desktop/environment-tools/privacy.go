package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maximumFrame = 4 * 1024 * 1024

type Rule struct {
	ID        string   `json:"id"`
	Value     string   `json:"value"`
	Encodings []string `json:"encodings,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}
type Policy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}
type replacement struct{ value, label string }
type scopedReplacement struct {
	path   string
	tokens []string
	pairs  []replacement
}
type Filter struct {
	version int
	pairs   []replacement
	scopes  []scopedReplacement
}
type Counts struct {
	Messages                      int64  `json:"messages"`
	Replacements                  int64  `json:"replacements"`
	UninspectedBinaryBlocks       int64  `json:"uninspectedBinaryBlocks"`
	PolicyVersion                 int    `json:"policyVersion"`
	Coverage                      string `json:"coverage"`
	ConfiguredPaths               int64  `json:"configuredPaths"`
	ScopedPathChecks              int64  `json:"scopedPathChecks"`
	ScopedPathsMatched            int64  `json:"scopedPathsMatched"`
	ScopedPathsMissing            int64  `json:"scopedPathsMissing"`
	ScopedPathsNonString          int64  `json:"scopedPathsNonString"`
	ScopedPathsProtected          int64  `json:"scopedPathsProtected"`
	ScopedEmbeddedFieldsProtected int64  `json:"scopedEmbeddedFieldsProtected"`
	ScopedDepthLimitSkipped       int64  `json:"scopedDepthLimitSkipped"`
	ScopedEmbeddedJSONUnparsed    int64  `json:"scopedEmbeddedJSONUnparsed"`
	OutputLimitFailures           int64  `json:"outputLimitFailures"`
	outputExceeded                bool
}

func newFilter(p Policy) (*Filter, error) {
	if (p.Version != 1 && p.Version != 2) || len(p.Rules) > 128 || (p.Version == 2 && len(p.Rules) == 0) {
		return nil, errors.New("POLICY_VERSION_OR_RULE_LIMIT")
	}
	ids, values := map[string]bool{}, map[string]string{}
	validID := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	f := &Filter{version: p.Version}
	scopes := map[string]*scopedReplacement{}
	scopedValues := map[string]map[string]string{}
	for _, r := range p.Rules {
		if !validID.MatchString(r.ID) || ids[r.ID] || len(r.Value) < 8 || len(r.Value) > 4096 || !utf8.ValidString(r.Value) || strings.ContainsRune(r.Value, 0) || strings.Contains(r.Value, "[HONGAI:") {
			return nil, errors.New("INVALID_OR_AMBIGUOUS_POLICY_RULE")
		}
		ids[r.ID] = true
		if p.Version == 1 && len(r.Paths) != 0 {
			return nil, errors.New("SCOPED_PATHS_REQUIRE_POLICY_V2")
		}
		if p.Version == 2 {
			if len(r.Paths) == 0 || len(r.Paths) > 32 {
				return nil, errors.New("POLICY_V2_NONEMPTY_EXACT_PATHS_REQUIRED")
			}
			seen := map[string]bool{}
			for _, path := range r.Paths {
				tokens, e := privacyPointer(path)
				if e != nil {
					return nil, e
				}
				if seen[path] {
					return nil, errors.New("POLICY_DUPLICATE_EXACT_PATH")
				}
				seen[path] = true
				if scopes[path] == nil {
					if len(scopes) >= 256 {
						return nil, errors.New("POLICY_EXACT_PATH_LIMIT")
					}
					scopes[path] = &scopedReplacement{path: path, tokens: tokens}
					scopedValues[path] = map[string]string{}
				}
			}
		}
		variants := []string{r.Value}
		for _, enc := range r.Encodings {
			switch enc {
			case "plain":
			case "url":
				variants = append(variants, url.QueryEscape(r.Value), strings.ReplaceAll(url.QueryEscape(r.Value), "+", "%20"), url.PathEscape(r.Value))
			case "base64":
				for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					variants = append(variants, e.EncodeToString([]byte(r.Value)))
				}
			default:
				return nil, errors.New("UNSUPPORTED_ENCODING_RULE")
			}
		}
		label := "[HONGAI:" + r.ID + "]"
		for _, v := range variants {
			if p.Version == 2 {
				for _, path := range r.Paths {
					if prior, ok := scopedValues[path][v]; ok {
						if prior != label {
							return nil, errors.New("AMBIGUOUS_SCOPED_POLICY_VALUE")
						}
						continue
					}
					scopedValues[path][v] = label
					scopes[path].pairs = append(scopes[path].pairs, replacement{v, label})
				}
				continue
			}
			if prior, ok := values[v]; ok {
				if prior != label {
					return nil, errors.New("AMBIGUOUS_POLICY_VALUE")
				}
				continue
			}
			values[v] = label
			f.pairs = append(f.pairs, replacement{v, label})
		}
	}
	sortPrivacyPairs(f.pairs)
	paths := make([]string, 0, len(scopes))
	for path := range scopes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		sortPrivacyPairs(scopes[path].pairs)
		f.scopes = append(f.scopes, *scopes[path])
	}
	if p.Version == 2 {
		labels, literals := map[string]bool{}, map[string]bool{}
		for _, scope := range f.scopes {
			for _, pair := range scope.pairs {
				labels[pair.label] = true
				literals[pair.value] = true
			}
		}
		for label := range labels {
			for literal := range literals {
				if strings.Contains(label, literal) {
					return nil, errors.New("POLICY_VALUE_COLLIDES_WITH_REPLACEMENT_LABEL")
				}
			}
		}
	}
	return f, nil
}

func sortPrivacyPairs(pairs []replacement) {
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].value) == len(pairs[j].value) {
			return pairs[i].value < pairs[j].value
		}
		return len(pairs[i].value) > len(pairs[j].value)
	})
}

func privacyProtectedKey(key string) bool {
	switch strings.ToLower(key) {
	case "jsonrpc", "id", "method", "uri", "progresstoken", "nextcursor", "inputschema", "outputschema", "binary", "blob", "name", "type", "mimetype", "protocolversion":
		return true
	}
	return false
}

// RFC 6901 pointers are message-absolute and select one value, not a subtree.
// Arrays are resolved at runtime; there is no wildcard or recursive selector.
func privacyPointer(path string) ([]string, error) {
	if path == "" || len(path) > 1024 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) || path[0] != '/' {
		return nil, errors.New("POLICY_RFC6901_EXACT_POINTER_REQUIRED")
	}
	raw := strings.Split(path[1:], "/")
	if len(raw) > 48 || (raw[0] != "result" && raw[0] != "error") {
		return nil, errors.New("POLICY_ONLY_RESULT_OR_ERROR_PATHS_ALLOWED")
	}
	tokens := make([]string, len(raw))
	for i, part := range raw {
		var token strings.Builder
		for pos := 0; pos < len(part); pos++ {
			if part[pos] != '~' {
				token.WriteByte(part[pos])
				continue
			}
			pos++
			if pos >= len(part) || (part[pos] != '0' && part[pos] != '1') {
				return nil, errors.New("POLICY_RFC6901_ESCAPE_INVALID")
			}
			if part[pos] == '0' {
				token.WriteByte('~')
			} else {
				token.WriteByte('/')
			}
		}
		tokens[i] = token.String()
		if strings.Contains(tokens[i], "*") || strings.Contains(tokens[i], "\x00") {
			return nil, errors.New("POLICY_WILDCARD_PATH_NOT_SUPPORTED")
		}
		if privacyProtectedKey(tokens[i]) {
			return nil, errors.New("POLICY_PROTECTED_PROTOCOL_OR_BINARY_PATH")
		}
	}
	return tokens, nil
}

// Longest-match, single pass: replacement labels cannot be processed as input.
func (f *Filter) text(s string) (string, int64, bool) {
	return replacePrivacyText(s, f.pairs)
}

func replacePrivacyText(s string, pairs []replacement) (string, int64, bool) {
	var out strings.Builder
	var count int64
	for pos := 0; pos < len(s); {
		matched := false
		for _, p := range pairs {
			if strings.HasPrefix(s[pos:], p.value) {
				if out.Len()+len(p.label) > maximumFrame {
					return "", count, true
				}
				out.WriteString(p.label)
				pos += len(p.value)
				count++
				matched = true
				break
			}
		}
		if !matched {
			if out.Len()+1 > maximumFrame {
				return "", count, true
			}
			out.WriteByte(s[pos])
			pos++
		}
	}
	return out.String(), count, false
}

func privacyBinaryObject(value map[string]any) bool {
	kind, _ := value["type"].(string)
	switch strings.ToLower(kind) {
	case "image", "audio", "blob", "binary":
		return true
	}
	_, mime := value["mimeType"].(string)
	_, data := value["data"].(string)
	_, blob := value["blob"].(string)
	_, binary := value["binary"].(string)
	return mime && (data || blob || binary)
}

func (f *Filter) scopedWalk(value any, depth int, pairs []replacement, stats *Counts) any {
	if depth > 48 {
		stats.ScopedDepthLimitSkipped++
		return value
	}
	switch x := value.(type) {
	case string:
		if depth < 8 && len(x) <= maximumFrame && (strings.HasPrefix(strings.TrimSpace(x), "{") || strings.HasPrefix(strings.TrimSpace(x), "[")) {
			if nested, e := strictJSON([]byte(x)); e == nil {
				before := stats.Replacements
				filtered := f.scopedWalk(nested, depth+1, pairs, stats)
				if stats.Replacements != before {
					budget := int64(maximumFrame)
					if stats.outputExceeded || !privacyJSONFits(filtered, &budget) {
						stats.outputExceeded = true
						return x
					}
					b, _ := json.Marshal(filtered)
					return string(b)
				}
				// Do not fall back to replacing raw serialized JSON: that would
				// change skipped routing/schema/binary fields inside the text.
				return x
			}
			stats.ScopedEmbeddedJSONUnparsed++
		}
		masked, n, exceeded := replacePrivacyText(x, pairs)
		if exceeded {
			stats.outputExceeded = true
			return x
		}
		stats.Replacements += n
		return masked
	case []any:
		for i, item := range x {
			x[i] = f.scopedWalk(item, depth+1, pairs, stats)
		}
		return x
	case map[string]any:
		if privacyBinaryObject(x) {
			stats.UninspectedBinaryBlocks++
			return x
		}
		for key, item := range x {
			if privacyProtectedKey(key) {
				stats.ScopedEmbeddedFieldsProtected++
				continue
			}
			x[key] = f.scopedWalk(item, depth+1, pairs, stats)
		}
		return x
	default:
		return value
	}
}

func (f *Filter) applyScoped(value any, scope scopedReplacement, depth int, stats *Counts) any {
	if depth == len(scope.tokens) {
		if _, ok := value.(string); !ok {
			stats.ScopedPathsNonString++
			return value
		}
		stats.ScopedPathsMatched++
		return f.scopedWalk(value, 0, scope.pairs, stats)
	}
	switch current := value.(type) {
	case map[string]any:
		if privacyBinaryObject(current) {
			stats.ScopedPathsProtected++
			stats.UninspectedBinaryBlocks++
			return value
		}
		key := scope.tokens[depth]
		item, ok := current[key]
		if !ok {
			stats.ScopedPathsMissing++
			return value
		}
		current[key] = f.applyScoped(item, scope, depth+1, stats)
	case []any:
		key := scope.tokens[depth]
		index, e := strconv.Atoi(key)
		if e != nil || index < 0 || index >= len(current) || strconv.Itoa(index) != key {
			stats.ScopedPathsMissing++
			return value
		}
		current[index] = f.applyScoped(current[index], scope, depth+1, stats)
	default:
		stats.ScopedPathsMissing++
	}
	return value
}

func strictJSON(data []byte) (any, error) {
	if len(data) > maximumFrame || !utf8.Valid(data) {
		return nil, errors.New("FRAME_SIZE_OR_ENCODING")
	}
	// Reject duplicate members, excessive nesting and trailing values before use.
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var consume func(int) error
	consume = func(depth int) error {
		if depth > 48 {
			return errors.New("JSON_DEPTH_LIMIT")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if mark, ok := t.(json.Delim); ok {
			switch mark {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("DUPLICATE_JSON_MEMBER")
					}
					seen[key] = true
					if e = consume(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := consume(depth + 1); e != nil {
						return e
					}
				}
			default:
				return errors.New("UNEXPECTED_JSON_DELIMITER")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := consume(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("JSON_TRAILING_VALUE")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func (f *Filter) walk(v any, depth int, stats *Counts) any {
	if depth > 48 {
		return v
	}
	switch x := v.(type) {
	case string:
		// JSON-in-text is decoded to handle escaped literal values. Ordinary file
		// text remains text, and is not reformatted when nothing changes.
		if depth < 8 && len(x) <= maximumFrame && (strings.HasPrefix(strings.TrimSpace(x), "{") || strings.HasPrefix(strings.TrimSpace(x), "[")) {
			if nested, e := strictJSON([]byte(x)); e == nil {
				before := stats.Replacements
				filtered := f.walk(nested, depth+1, stats)
				if stats.Replacements != before {
					budget := int64(maximumFrame)
					if stats.outputExceeded || !privacyJSONFits(filtered, &budget) {
						stats.outputExceeded = true
						return x
					}
					b, _ := json.Marshal(filtered)
					return string(b)
				}
			}
		}
		masked, n, exceeded := f.text(x)
		if exceeded {
			stats.outputExceeded = true
			return x
		}
		stats.Replacements += n
		return masked
	case []any:
		for i, item := range x {
			x[i] = f.walk(item, depth+1, stats)
		}
		return x
	case map[string]any:
		kind, _ := x["type"].(string)
		if kind == "image" || kind == "audio" || kind == "blob" {
			stats.UninspectedBinaryBlocks++
			return x
		}
		for k, item := range x {
			if k == "blob" {
				if _, ok := x["mimeType"].(string); ok {
					stats.UninspectedBinaryBlocks++
					continue
				}
			}
			// Do not mutate identifiers, schemas, transport or routing fields.
			if k == "uri" || k == "progressToken" || k == "nextCursor" || k == "inputSchema" || k == "outputSchema" {
				continue
			}
			x[k] = f.walk(item, depth+1, stats)
		}
		return x
	default:
		return v
	}
}

func (f *Filter) message(data []byte, stats *Counts) ([]byte, error) {
	v, e := strictJSON(data)
	if e != nil {
		return nil, errors.New("UPSTREAM_INVALID_JSON")
	}
	m, ok := v.(map[string]any)
	if !ok || m["jsonrpc"] != "2.0" {
		return nil, errors.New("UPSTREAM_INVALID_JSONRPC")
	}
	_, request := m["method"].(string)
	_, result := m["result"]
	_, failure := m["error"]
	if !request && !result && !failure {
		return nil, errors.New("UPSTREAM_INVALID_MESSAGE")
	}
	stats.Messages++
	stats.outputExceeded = false
	stats.PolicyVersion = f.version
	if f.version == 2 {
		stats.Coverage = "EXACT_JSON_POINTER_STRING_VALUES_ONLY"
		stats.ConfiguredPaths = int64(len(f.scopes))
		for _, scope := range f.scopes {
			stats.ScopedPathChecks++
			f.applyScoped(m, scope, 0, stats)
		}
	} else {
		stats.Coverage = "LEGACY_LITERAL_CONTENT_FILTER_BINARY_EXCLUDED"
		if value, ok := m["result"]; ok {
			m["result"] = f.walk(value, 0, stats)
		}
		if value, ok := m["error"]; ok {
			m["error"] = f.walk(value, 0, stats)
		}
		if value, ok := m["params"]; ok {
			m["params"] = f.walk(value, 0, stats)
		}
	}
	remaining := int64(maximumFrame)
	if stats.outputExceeded || !privacyJSONFits(m, &remaining) {
		stats.OutputLimitFailures++
		return nil, errors.New("FILTERED_OUTPUT_FRAME_LIMIT")
	}
	out, e := json.Marshal(m)
	if e != nil {
		return nil, fmt.Errorf("ENCODE_FILTERED_MESSAGE")
	}
	if len(out) > maximumFrame {
		stats.OutputLimitFailures++
		return nil, errors.New("FILTERED_OUTPUT_FRAME_LIMIT")
	}
	return out, nil
}

// Count encoding/json's representation without allocating an expanded output.
// This includes HTML escaping and Unicode separators, not just string lengths.
func privacyJSONFits(value any, remaining *int64) bool {
	consume := func(n int64) bool {
		*remaining -= n
		return *remaining >= 0
	}
	switch x := value.(type) {
	case nil:
		return consume(4)
	case bool:
		if x {
			return consume(4)
		}
		return consume(5)
	case json.Number:
		return consume(int64(len(x.String())))
	case string:
		if !consume(2) {
			return false
		}
		for i := 0; i < len(x); {
			c := x[i]
			n := 1
			if c < utf8.RuneSelf {
				switch c {
				case '\\', '"', '\b', '\f', '\n', '\r', '\t':
					n = 2
				case '<', '>', '&':
					n = 6
				default:
					if c < 0x20 {
						n = 6
					}
				}
				i++
			} else {
				r, size := utf8.DecodeRuneInString(x[i:])
				n = size
				if (r == utf8.RuneError && size == 1) || r == '\u2028' || r == '\u2029' {
					n = 6
				}
				i += size
			}
			if !consume(int64(n)) {
				return false
			}
		}
		return true
	case []any:
		if !consume(2) {
			return false
		}
		for i, item := range x {
			if i > 0 && !consume(1) {
				return false
			}
			if !privacyJSONFits(item, remaining) {
				return false
			}
		}
		return true
	case map[string]any:
		if !consume(2) {
			return false
		}
		first := true
		for key, item := range x {
			if !first && !consume(1) {
				return false
			}
			first = false
			if !privacyJSONFits(key, remaining) || !consume(1) || !privacyJSONFits(item, remaining) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
