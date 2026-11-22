package canon

import (
	"bytes"
	"testing"
)

func TestMarshalDeterministicKeyOrder(t *testing.T) {
	a := map[string]any{"b": 1, "a": map[string]any{"z": "x", "y": []any{1, "two", true}}}
	b := map[string]any{"a": map[string]any{"y": []any{1, "two", true}, "z": "x"}, "b": 1}
	ba, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ba, bb) {
		t.Fatalf("encodings differ:\n%s\n%s", ba, bb)
	}
}

func TestMarshalStructMatchesMap(t *testing.T) {
	type inner struct {
		Z string `json:"z"`
		Y []int  `json:"y"`
	}
	type outer struct {
		B int   `json:"b"`
		A inner `json:"a"`
	}
	fromStruct := MustMarshal(outer{B: 1, A: inner{Z: "x", Y: []int{1, 2}}})
	want := `{"a":{"y":[1,2],"z":"x"},"b":1}`
	if string(fromStruct) != want {
		t.Fatalf("got %s want %s", fromStruct, want)
	}
}

func TestMarshalNoHTMLEscaping(t *testing.T) {
	got := MustMarshal(map[string]string{"k": "<&>"})
	if string(got) != `{"k":"<&>"}` {
		t.Fatalf("got %s", got)
	}
}
