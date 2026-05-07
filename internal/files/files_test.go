package files

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeEmpty(t *testing.T) {
	m := Manifest{SchemaVersion: SchemaVersion, Algorithm: Algorithm}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"algorithm":"sha256","entries":[]}` + "\n"
	if string(got) != want {
		t.Errorf("Encode mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeNilEntriesNormalize(t *testing.T) {
	m := Manifest{SchemaVersion: SchemaVersion, Algorithm: Algorithm, Entries: nil}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("null")) {
		t.Errorf("nil Entries encoded as null:\n%s", got)
	}
	if !bytes.Contains(got, []byte(`"entries":[]`)) {
		t.Errorf("nil Entries did not normalize to []:\n%s", got)
	}
}

func TestEncodeTrailingNewline(t *testing.T) {
	m := Manifest{SchemaVersion: SchemaVersion, Algorithm: Algorithm}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Error("output missing trailing newline")
	}
	if bytes.HasSuffix(got, []byte("\n\n")) {
		t.Error("output has more than one trailing newline")
	}
}

func TestEncodeFieldOrder(t *testing.T) {
	m := Manifest{SchemaVersion: SchemaVersion, Algorithm: Algorithm}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	out := string(got)
	wantOrder := []string{`"schema_version"`, `"algorithm"`, `"entries"`}
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(out, k)
		if i < 0 {
			t.Errorf("missing field %s", k)
			continue
		}
		if i <= last {
			t.Errorf("field %s out of order", k)
		}
		last = i
	}
}

func TestHashFile(t *testing.T) {
	hash, size, err := HashFile(strings.NewReader("Hello, Peios!\n"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "4f91e7c17054930fd12bf2de72f8f31eb44090052475b88dc2338163d642e7ac"
	if hash != want {
		t.Errorf("hash %q, want %q", hash, want)
	}
	if size != 14 {
		t.Errorf("size %d, want 14", size)
	}
}
