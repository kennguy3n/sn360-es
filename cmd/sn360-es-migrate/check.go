package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// migrationFileRe enforces the golang-migrate naming convention:
// 4-digit zero-padded version, snake_case name, .up.sql or .down.sql.
var migrationFileRe = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$`)

// checkMigrations validates filenames, ensures every up has a matching
// down, runs a minimal SQL sanity check, and returns a non-nil error if
// anything is wrong. It does NOT touch the database.
func checkMigrations(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}

	type pair struct {
		up   string
		down string
	}
	versions := map[int]*pair{}
	names := map[int]string{}

	var problems []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s: filename does not match {version}_{name}.{up|down}.sql", e.Name()))
			continue
		}
		ver, _ := strconv.Atoi(m[1])
		name := m[2]
		direction := m[3]

		if existing, ok := names[ver]; ok && existing != name {
			problems = append(problems, fmt.Sprintf("version %04d: conflicting names %q vs %q", ver, existing, name))
		}
		names[ver] = name

		p := versions[ver]
		if p == nil {
			p = &pair{}
			versions[ver] = p
		}
		switch direction {
		case "up":
			if p.up != "" {
				problems = append(problems, fmt.Sprintf("version %04d: duplicate .up.sql files", ver))
			}
			p.up = e.Name()
		case "down":
			if p.down != "" {
				problems = append(problems, fmt.Sprintf("version %04d: duplicate .down.sql files", ver))
			}
			p.down = e.Name()
		}
	}

	if len(versions) == 0 {
		problems = append(problems, "no migration files found")
	}

	ordered := make([]int, 0, len(versions))
	for v := range versions {
		ordered = append(ordered, v)
	}
	sort.Ints(ordered)

	// Ensure versions are contiguous starting at 1.
	for i, v := range ordered {
		if v != i+1 {
			problems = append(problems, fmt.Sprintf("non-contiguous version: expected %04d, got %04d", i+1, v))
		}
		p := versions[v]
		if p.up == "" {
			problems = append(problems, fmt.Sprintf("version %04d: missing .up.sql", v))
		}
		if p.down == "" {
			problems = append(problems, fmt.Sprintf("version %04d: missing .down.sql", v))
		}
		for _, f := range []string{p.up, p.down} {
			if f == "" {
				continue
			}
			if err := sanityCheckSQL(filepath.Join(abs, f)); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", f, err))
			}
		}
	}

	if len(problems) > 0 {
		return errors.New("migrate check failed:\n  - " + strings.Join(problems, "\n  - "))
	}
	fmt.Printf("migrate check OK: %d migration pair(s) under %s\n", len(versions), abs)
	return nil
}

// sanityCheckSQL applies a deliberately conservative syntax sniff so we
// can reject the most common authoring mistakes (empty files,
// unbalanced BEGIN/COMMIT, missing trailing semicolon) without running a
// real SQL parser. Anything that needs deeper validation should be
// caught by integration tests against a real Postgres container.
func sanityCheckSQL(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return errors.New("empty SQL file")
	}
	stripped := stripSQLNoise(text)
	upper := strings.ToUpper(stripped)
	begins := strings.Count(upper, "BEGIN;")
	commits := strings.Count(upper, "COMMIT;")
	if begins != commits {
		return fmt.Errorf("unbalanced BEGIN/COMMIT (begins=%d commits=%d)", begins, commits)
	}
	if !strings.HasSuffix(text, ";") {
		return errors.New("file does not end with `;`")
	}
	return nil
}

// stripSQLNoise removes single-line `-- …` comments, `/* … */` block
// comments, and single-quoted string literals (with `”` escapes) so
// downstream token counts ignore tokens that don't represent executable
// SQL. The result preserves the original line structure — comments and
// strings are replaced with spaces rather than excised — so error
// messages computed against the stripped text still point at the
// right column. We do not handle PostgreSQL dollar-quoted bodies
// (`$$ … $$`) because migrations in this repo do not currently use
// them; if that changes, extend this routine before relying on its
// output.
func stripSQLNoise(s string) string {
	out := make([]byte, 0, len(s))
	var (
		inLine  bool // inside `-- ...` until newline
		inBlock bool // inside `/* ... */`
		inStr   bool // inside single-quoted string
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				out = append(out, c)
			} else {
				out = append(out, ' ')
			}
		case inBlock:
			switch {
			case c == '*' && i+1 < len(s) && s[i+1] == '/':
				inBlock = false
				out = append(out, ' ', ' ')
				i++
			case c == '\n':
				out = append(out, c)
			default:
				out = append(out, ' ')
			}
		case inStr:
			// `''` is an escaped single quote inside a string;
			// stay in-string for both bytes.
			if c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				out = append(out, ' ', ' ')
				i++
				continue
			}
			switch c {
			case '\'':
				inStr = false
				out = append(out, ' ')
			case '\n':
				out = append(out, c)
			default:
				out = append(out, ' ')
			}
		default:
			if c == '-' && i+1 < len(s) && s[i+1] == '-' {
				inLine = true
				out = append(out, ' ', ' ')
				i++
				continue
			}
			if c == '/' && i+1 < len(s) && s[i+1] == '*' {
				inBlock = true
				out = append(out, ' ', ' ')
				i++
				continue
			}
			if c == '\'' {
				inStr = true
				out = append(out, ' ')
				continue
			}
			out = append(out, c)
		}
	}
	return string(out)
}
