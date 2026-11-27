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
	"strings"
	"unicode/utf8"
)

const maximumFrame = 4 * 1024 * 1024

type Rule struct {
	ID        string   `json:"id"`
	Value     string   `json:"value"`
	Encodings []string `json:"encodings,omitempty"`
}
type Policy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}
type replacement struct{ value, label string }
type Filter struct{ pairs []replacement }
type Counts struct {
	Messages                int64 `json:"messages"`
	Replacements            int64 `json:"replacements"`
	UninspectedBinaryBlocks int64 `json:"uninspectedBinaryBlocks"`
}

func newFilter(p Policy) (*Filter, error) {
	if p.Version != 1 || len(p.Rules) > 128 {
		return nil, errors.New("POLICY_VERSION_OR_RULE_LIMIT")
	}
	ids, values := map[string]bool{}, map[string]string{}
	validID := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	f := &Filter{}
	for _, r := range p.Rules {
		if !validID.MatchString(r.ID) || ids[r.ID] || len(r.Value) < 8 || len(r.Value) > 4096 || !utf8.ValidString(r.Value) || strings.ContainsRune(r.Value, 0) || strings.Contains(r.Value, "[HONGAI:") {
			return nil, errors.New("INVALID_OR_AMBIGUOUS_POLICY_RULE")
		}
		ids[r.ID] = true
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
	sort.Slice(f.pairs, func(i, j int) bool {
		if len(f.pairs[i].value) == len(f.pairs[j].value) {
			return f.pairs[i].value < f.pairs[j].value
		}
		return len(f.pairs[i].value) > len(f.pairs[j].value)
	})
	return f, nil
}

// Longest-match, single pass: replacement labels cannot be processed as input.
func (f *Filter) text(s string) (string, int64) {
	var out strings.Builder
	var count int64
	for pos := 0; pos < len(s); {
		matched := false
		for _, p := range f.pairs {
			if strings.HasPrefix(s[pos:], p.value) {
				out.WriteString(p.label)
				pos += len(p.value)
				count++
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(s[pos])
			pos++
		}
	}
	return out.String(), count
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
					b, _ := json.Marshal(filtered)
					return string(b)
				}
			}
		}
		masked, n := f.text(x)
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
	if value, ok := m["result"]; ok {
		m["result"] = f.walk(value, 0, stats)
	}
	if value, ok := m["error"]; ok {
		m["error"] = f.walk(value, 0, stats)
	}
	if value, ok := m["params"]; ok {
		m["params"] = f.walk(value, 0, stats)
	}
	out, e := json.Marshal(m)
	if e != nil {
		return nil, fmt.Errorf("ENCODE_FILTERED_MESSAGE")
	}
	return out, nil
}
