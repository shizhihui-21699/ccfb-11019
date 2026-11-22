// Package canon provides a deterministic JSON encoding used for all
// signature payloads in this service.
//
// Signature reproducibility across implementations (Go service, vehicle
// firmware, mobile app) is a security requirement: if two verifiers disagree
// on the bytes that were signed, an attacker can pick whichever encoding
// passes. Marshal therefore sorts object keys, emits no insignificant
// whitespace, disables HTML escaping and preserves numeric literals.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Marshal returns the canonical JSON encoding of v.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := write(&buf, x); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustMarshal is Marshal for payloads that are known to be encodable.
func MustMarshal(v any) []byte {
	b, err := Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("canon: %v", err))
	}
	return b
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case float64:
		return fmt.Errorf("canon: unnormalised float %v (decode with UseNumber)", t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	start := buf.Len()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	// Encoder.Encode appends a newline; trim it so the output is exact.
	buf.Truncate(buf.Len() - 1)
	_ = start
	return nil
}
