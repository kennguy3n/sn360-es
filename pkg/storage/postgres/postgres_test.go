package postgres

import (
	"strings"
	"testing"
)

func TestConfig_DSN(t *testing.T) {
	c := Config{Host: "h", Port: 5432, User: "u", Password: "p", Database: "d"}
	got := c.DSN()
	want := "host=h port=5432 user=u password=p dbname=d sslmode=disable"
	if got != want {
		t.Fatalf("DSN(): got=%q want=%q", got, want)
	}
}

func TestConfig_URL(t *testing.T) {
	c := Config{Host: "h", Port: 5432, User: "u", Password: "p", Database: "d", SSLMode: "require"}
	got := c.URL()
	if !strings.HasPrefix(got, "postgres://u:p@h:5432/d") {
		t.Fatalf("URL prefix: got=%q", got)
	}
	if !strings.Contains(got, "sslmode=require") {
		t.Fatalf("URL sslmode: got=%q", got)
	}
}

func TestParseURL(t *testing.T) {
	cfg, err := ParseURL("postgres://alice:secret@db.local:6543/sn?sslmode=require")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if cfg.User != "alice" || cfg.Password != "secret" || cfg.Host != "db.local" ||
		cfg.Port != 6543 || cfg.Database != "sn" || cfg.SSLMode != "require" {
		t.Fatalf("ParseURL fields wrong: %+v", cfg)
	}
}

func TestParseURL_BadScheme(t *testing.T) {
	if _, err := ParseURL("mysql://x/y"); err == nil {
		t.Fatalf("expected error for non-postgres scheme")
	}
}

func TestQuotedIdent(t *testing.T) {
	cases := map[string]string{
		"plain":   `"plain"`,
		`weir"d`:  `"weir""d"`,
		"":        `""`,
		"snake_1": `"snake_1"`,
	}
	for in, want := range cases {
		if got := QuotedIdent(in); got != want {
			t.Fatalf("QuotedIdent(%q): got=%q want=%q", in, got, want)
		}
	}
}
