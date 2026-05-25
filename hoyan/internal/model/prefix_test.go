package model

import "testing"

func TestParsePrefixCanonicalizes(t *testing.T) {
	pfx, err := ParsePrefix("10.0.0.1/24")
	if err != nil {
		t.Fatalf("ParsePrefix() error = %v", err)
	}
	if got, want := pfx.String(), "10.0.0.0/24"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestPrefixEqualCanonicalForms(t *testing.T) {
	a, err := ParsePrefix("10.0.0.1/24")
	if err != nil {
		t.Fatalf("ParsePrefix(a) error = %v", err)
	}
	b, err := ParsePrefix("10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParsePrefix(b) error = %v", err)
	}
	if !a.Equal(b) {
		t.Fatalf("%s Equal(%s) = false, want true", a, b)
	}
}

func TestParsePrefixRejectsInvalidPrefix(t *testing.T) {
	if _, err := ParsePrefix("not-a-prefix"); err == nil {
		t.Fatalf("ParsePrefix() error = nil, want error")
	}
}
