// Command sn360-es-license-check enforces the project's license allow-list
// across all module dependencies, replacing google/go-licenses for the CI
// gate (go-licenses 1.x and 2.x both regress on Go 1.21+ toolchain layout:
// they treat every stdlib package as "missing module info" and emit a
// fatal exit; see https://github.com/google/go-licenses/issues/128).
//
// Approach:
//
//  1. `go list -m -mod=readonly -json all` enumerates every module the
//     build links against (direct + transitive).
//  2. For each non-main, non-stdlib module, read its on-disk LICENSE-like
//     file from GOMODCACHE and classify with deterministic substring
//     heuristics keyed on canonical license boilerplate.
//  3. Classify into one of: ALLOW (permissive, OK), WARN (weak copyleft
//     that's acceptable for library deps but worth surfacing), DENY
//     (forbidden, fail the build), UNKNOWN (no LICENSE file or no
//     classifier match — fail unless explicitly waivered in an
//     allow-list file at repo root).
//
// Allow-list rationale (kept narrow on purpose, expand via review):
//
//   - MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0: standard
//     permissive, no copyleft, no patent surprises.
//   - MPL-2.0: file-level weak copyleft; we don't modify upstream MPL
//     files so we're not triggering its share-back clause.
//   - Unlicense, CC0-1.0, BSL-1.0: public-domain-equivalent.
//
// Deny-list (any reverse-classification hit fails the build):
//
//   - GPL-2.0, GPL-3.0, LGPL-*, AGPL-*: viral / network-clause
//     copyleft incompatible with a closed-source commercial SaaS.
//   - SSPL: MongoDB's source-available license; not OSI-approved
//     and SaaS-hostile.
//   - Server Side Public License (alt spelling), Commons Clause:
//     same posture.
//
// UNKNOWN handling: a module without a detectable LICENSE file is a
// supply-chain risk (could be anything — including GPL). The default
// policy is to fail; an explicit waiver in `.license-waivers.txt` at
// repo root can override on a per-module basis, with a justification
// comment required on the line above.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// module mirrors the relevant subset of `go list -m -json` output.
type module struct {
	Path     string
	Version  string
	Main     bool
	Dir      string
	Indirect bool
}

// classification is the verdict for a single module's license.
//
// classWaivered is distinct from classUnknown so the report can show
// reviewers exactly how many modules are explicitly accepted via the
// .license-waivers.txt allow-list — vs. how many are genuinely
// unrecognised and require operator attention. Lumping the two under
// classUnknown made the summary line ambiguous ("2 UNKNOWN" — were
// they waivered or do I need to act?) and forced a brittle string
// prefix check on f.Note in the exit-code path.
type classification int

const (
	classAllow classification = iota
	classWarn
	classDeny
	classUnknown
	classWaivered
)

func (c classification) String() string {
	switch c {
	case classAllow:
		return "ALLOW"
	case classWarn:
		return "WARN"
	case classDeny:
		return "DENY"
	case classWaivered:
		return "WAIVERED"
	default:
		return "UNKNOWN"
	}
}

// licenseRule pairs a SPDX identifier with the canonical phrases that
// uniquely identify its boilerplate. The matcher requires ALL phrases
// in `mustContain` to appear in the LICENSE *title* region (first
// `titleHeadBytes` bytes, case-insensitive) AND none of the phrases in
// `mustNotContain` to also appear in the same title region. This keeps
// the classifier deterministic without pulling in a 5 MB licenseclassifier
// dependency, while still being precise enough to distinguish e.g.
// GPL-2.0 from LGPL-2.1 (both share most boilerplate but LGPL has an
// explicit "Lesser" prefix in the title) and avoiding cross-license
// false positives from compatibility clauses (MPL-2.0 §3.3 references
// "Lesser General Public License" by name, which would otherwise trip
// the LGPL rule on an actually-MPL module like pgregory.net/rapid).
//
// Why mustNotContain matches against the title head and NOT the full
// text: the canonical GPL-3.0 license is ~35 KiB and includes an
// appendix paragraph ("… we recommend that you use the GNU Lesser
// General Public License instead …") which would trip a full-text
// `mustNotContain: ["lesser general public license"]` and bounce the
// rule, causing real GPL-3.0 modules to fall through to UNKNOWN. The
// LGPL/AGPL exclusions belong on the TITLE because that is what
// distinguishes those families from plain GPL — body-text mentions in
// the appendix are noise, not signal.
type licenseRule struct {
	SPDX           string
	class          classification
	mustContain    []string // matched against the title head (first titleHeadBytes)
	mustNotContain []string // matched against the title head (first titleHeadBytes)
}

// titleHeadBytes is the size of the title window inspected by `mustContain`.
// Empirically, every canonical OSI/SPDX license places its identifying
// title within the first ~1500 bytes of the LICENSE file (heading +
// preamble); 2 KiB gives a comfortable margin while excluding the
// compatibility / patent sections that reference other licenses by name.
const titleHeadBytes = 2000

// rules ordered by specificity: more-restrictive rules (e.g. AGPL,
// LGPL variants) precede their parent (GPL) so that the LGPL boilerplate
// — which also matches several GPL phrases — is classified as LGPL.
var rules = []licenseRule{
	// Deny-list (matched first to short-circuit benign-looking modules
	// that ship dual-licensed text).
	{
		SPDX:        "AGPL-3.0",
		class:       classDeny,
		mustContain: []string{"affero general public license", "version 3"},
	},
	{
		SPDX:        "AGPL-1.0",
		class:       classDeny,
		mustContain: []string{"affero general public license"},
	},
	{
		SPDX:        "LGPL-3.0",
		class:       classDeny,
		mustContain: []string{"lesser general public license", "version 3"},
	},
	{
		SPDX:        "LGPL-2.1",
		class:       classDeny,
		mustContain: []string{"lesser general public license", "version 2"},
	},
	{
		SPDX:        "LGPL",
		class:       classDeny,
		mustContain: []string{"lesser general public license"},
	},
	{
		SPDX:        "GPL-3.0",
		class:       classDeny,
		mustContain: []string{"gnu general public license", "version 3"},
		mustNotContain: []string{
			"lesser general public license",
			"affero general public license",
		},
	},
	{
		SPDX:        "GPL-2.0",
		class:       classDeny,
		mustContain: []string{"gnu general public license", "version 2"},
		mustNotContain: []string{
			"lesser general public license",
			"affero general public license",
		},
	},
	{
		SPDX:        "GPL",
		class:       classDeny,
		mustContain: []string{"gnu general public license"},
		mustNotContain: []string{
			"lesser general public license",
			"affero general public license",
		},
	},
	{
		SPDX:        "SSPL",
		class:       classDeny,
		mustContain: []string{"server side public license"},
	},
	{
		SPDX:        "Commons-Clause",
		class:       classDeny,
		mustContain: []string{"commons clause"},
	},
	{
		SPDX:        "BUSL-1.1",
		class:       classDeny,
		mustContain: []string{"business source license"},
	},

	// Allow-list (matched after deny-list so a dual-licensed
	// "Apache OR GPL" module is correctly flagged as deny).
	{
		SPDX:        "Apache-2.0",
		class:       classAllow,
		mustContain: []string{"apache license", "version 2.0"},
	},
	{
		SPDX:        "MPL-2.0",
		class:       classAllow,
		mustContain: []string{"mozilla public license", "version 2.0"},
	},
	{
		SPDX:        "MPL-1.1",
		class:       classAllow,
		mustContain: []string{"mozilla public license", "version 1.1"},
	},
	{
		SPDX:        "BSD-3-Clause",
		class:       classAllow,
		mustContain: []string{"redistribution and use", "neither the name"},
	},
	{
		SPDX:           "BSD-2-Clause",
		class:          classAllow,
		mustContain:    []string{"redistribution and use"},
		mustNotContain: []string{"neither the name"},
	},
	{
		SPDX:        "ISC",
		class:       classAllow,
		mustContain: []string{"permission to use, copy, modify, and/or distribute"},
	},
	{
		SPDX:        "MIT",
		class:       classAllow,
		mustContain: []string{"permission is hereby granted, free of charge"},
	},
	{
		SPDX:        "Unlicense",
		class:       classAllow,
		mustContain: []string{"this is free and unencumbered software"},
	},
	{
		SPDX:        "CC0-1.0",
		class:       classAllow,
		mustContain: []string{"creative commons", "cc0"},
	},
	{
		SPDX:        "BSL-1.0",
		class:       classAllow,
		mustContain: []string{"boost software license"},
	},
	{
		SPDX:        "Zlib",
		class:       classAllow,
		mustContain: []string{"this software is provided 'as-is'", "no event will the authors"},
	},
}

// licenseFileNames are the conventional license filenames we look for,
// case-insensitively, at the module root.
var licenseFileNames = []string{
	"LICENSE",
	"LICENSE.md",
	"LICENSE.txt",
	"LICENCE",
	"LICENCE.md",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
	"COPYRIGHT",
	"COPYRIGHT.md",
	"COPYRIGHT.txt",
	"NOTICE",
	"NOTICE.md",
	"NOTICE.txt",
	"License",
	"License.md",
	"License.txt",
	"license",
	"license.md",
	"license.txt",
}

// finding is one row in the report.
type finding struct {
	Module  string
	Version string
	License string
	Class   classification
	File    string // relative to module Dir, "" if not found
	Note    string // for unknowns / waivered modules
}

func main() {
	var (
		jsonOut    string
		csvOut     string
		waiverFile string
		strict     bool
	)
	flag.StringVar(&jsonOut, "json", "", "write the full report as JSON to this path")
	flag.StringVar(&csvOut, "csv", "", "write the report as CSV (module,version,license,class) to this path")
	flag.StringVar(&waiverFile, "waivers", ".license-waivers.txt", "path to waiver file (one module path per line, '#' for comments)")
	flag.BoolVar(&strict, "strict", true, "fail on UNKNOWN classifications (no LICENSE file or no rule match)")
	flag.Parse()

	waivers, err := loadWaivers(waiverFile)
	if err != nil {
		fatal("failed to load waivers: %v", err)
	}

	modules, err := listModules()
	if err != nil {
		fatal("failed to list modules: %v", err)
	}

	findings := make([]finding, 0, len(modules))
	for _, m := range modules {
		if m.Main {
			continue
		}
		// Skip the stdlib explicitly. In Go 1.21+, `go list -m all`
		// can include a synthetic `std` (and `cmd`) entry with
		// Main=false and Dir pointing at GOROOT/src, which would
		// otherwise flow through the classifier (Go's LICENSE is
		// BSD-3-Clause so it'd land as ALLOW — harmless but noisy
		// in the report, and gives reviewers a false signal that
		// the tool is auditing the stdlib's license posture, which
		// it isn't). Filter by module Path rather than Dir-under-
		// GOROOT because the GOROOT layout has shifted across
		// recent Go versions and Path equality is stable.
		if m.Path == "std" || m.Path == "cmd" {
			continue
		}
		if m.Dir == "" {
			// Module was listed but not downloaded — typical for
			// modules that the main module declares but doesn't
			// actually compile in (e.g. test-only deps excluded
			// by `-mod=readonly`). Run `go mod download` if the
			// caller wants to catch these too.
			continue
		}
		f := classifyModule(m, waivers)
		findings = append(findings, f)
	}

	// Stable output ordering for diff-friendly reports.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Module < findings[j].Module
	})

	report(findings)
	if jsonOut != "" {
		if err := writeJSON(jsonOut, findings); err != nil {
			fatal("failed to write JSON report: %v", err)
		}
	}
	if csvOut != "" {
		if err := writeCSV(csvOut, findings); err != nil {
			fatal("failed to write CSV report: %v", err)
		}
	}

	// Determine exit code. classWaivered is intentionally NOT in the
	// failure path: the operator has explicitly accepted those modules
	// via .license-waivers.txt with a justification, and the report
	// surfaces them as a distinct class so reviewers can audit the
	// allow-list. classUnknown is what we fail on (in strict mode) —
	// those are modules where neither a rule matched nor a waiver
	// exists, which is the supply-chain risk we built this tool to
	// catch.
	var (
		denyCount    int
		unknownCount int
	)
	for _, f := range findings {
		switch f.Class {
		case classDeny:
			denyCount++
		case classUnknown:
			unknownCount++
		}
	}

	if denyCount > 0 {
		fatal("license check failed: %d module(s) carry a forbidden license", denyCount)
	}
	if strict && unknownCount > 0 {
		fatal("license check failed: %d module(s) have an unrecognised or missing LICENSE — add a waiver in %s with a justification, or relax with -strict=false", unknownCount, waiverFile)
	}
}

// listModules runs `go list -m -mod=readonly -json all` and parses the
// resulting JSON stream (one object per module, not a JSON array). A
// 5-minute timeout bounds the worst case (e.g. cold module cache that
// needs to download every dep) without blocking CI indefinitely.
func listModules() (mods []module, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-mod=readonly", "-json", "all")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Always reap the subprocess: on the early-return-on-decode-error
	// path, skipping Wait() leaves `go list` lingering until the 5-min
	// ctx timeout fires. The decode error is the authoritative one to
	// surface; the Wait() result is informational — if Wait fails AND
	// we already have a decode error, we keep the decode error and
	// log the wait failure to stderr (no other channel available
	// inside a deferred cleanup).
	defer func() {
		waitErr := cmd.Wait()
		if waitErr != nil && err == nil {
			err = fmt.Errorf("go list exited non-zero: %w", waitErr)
		}
	}()
	dec := json.NewDecoder(out)
	var modules []module
	for {
		var m module
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		modules = append(modules, m)
	}
	return modules, nil
}

// classifyModule reads the LICENSE-like file from the module's directory
// and matches it against the rules. Returns the verdict as a finding.
func classifyModule(m module, waivers map[string]string) finding {
	out := finding{
		Module:  m.Path,
		Version: m.Version,
		Class:   classUnknown,
	}

	licensePath, licenseText := readLicenseFile(m.Dir)
	if licenseText == "" {
		// Disambiguate "no LICENSE file present at all" from "file
		// is present but empty" — both collapse to UNKNOWN /
		// WAIVERED classification, but an operator triaging a
		// false-positive needs to know whether to add a LICENSE file
		// upstream (case 1) vs. fix a packaging bug that shipped an
		// empty one (case 2). readLicenseFile returns a non-empty
		// path iff a file was actually opened, so this branch is the
		// authoritative discriminator.
		var reason string
		if licensePath == "" {
			reason = "no LICENSE file found in " + m.Dir
		} else {
			reason = "LICENSE file " + filepath.Join(m.Dir, licensePath) + " is empty"
		}
		if just, ok := waivers[m.Path]; ok {
			out.Class = classWaivered
			out.Note = "waivered (" + reason + "): " + just
		} else {
			out.Note = reason
		}
		return out
	}
	out.File = licensePath

	normalised := strings.ToLower(licenseText)
	head := normalised
	if len(head) > titleHeadBytes {
		head = head[:titleHeadBytes]
	}
	for _, r := range rules {
		if matchesRule(head, r) {
			out.License = r.SPDX
			out.Class = r.class
			return out
		}
	}

	// No rule matched — either an unrecognised license or a custom
	// permissive that we haven't taught the classifier about yet.
	if just, ok := waivers[m.Path]; ok {
		out.Class = classWaivered
		out.Note = "waivered (no rule matched " + licensePath + "): " + just
	} else {
		out.Note = fmt.Sprintf("no rule matched %s (first non-empty line: %q)", licensePath, firstNonEmptyLine(licenseText))
	}
	return out
}

// matchesRule applies the mustContain and mustNotContain logic — both
// against the title head only. See the licenseRule doc comment for the
// rationale (the canonical GPL-3.0 appendix mentions LGPL by name, so
// a full-text scope would bounce every real GPL-3.0 module through to
// UNKNOWN).
func matchesRule(head string, r licenseRule) bool {
	for _, p := range r.mustContain {
		if !strings.Contains(head, p) {
			return false
		}
	}
	for _, p := range r.mustNotContain {
		if strings.Contains(head, p) {
			return false
		}
	}
	return true
}

// readLicenseFile scans `dir` for any of the conventional LICENSE filenames
// (case-sensitive on Linux). Returns (relative path, file contents) or
// ("", "") if none found. Reads at most 64 KiB to bound memory.
func readLicenseFile(dir string) (string, string) {
	const maxBytes int64 = 64 * 1024
	for _, name := range licenseFileNames {
		path := filepath.Join(dir, name)
		f, err := os.Open(path) //#nosec G304 -- name is from a hard-coded allow-list, dir is a Go module cache path resolved by `go list`
		if err != nil {
			continue
		}
		// io.ReadAll over io.LimitReader, not a single Read(): the
		// io.Reader contract permits a short read even on a local
		// filesystem, and a license-text classifier silently
		// processing a partial file is a correctness hazard — it
		// could miss the title-head boilerplate entirely on a slow
		// FUSE mount or fall into the UNKNOWN branch for a real GPL.
		// LimitReader caps the memory footprint at maxBytes.
		buf, readErr := io.ReadAll(io.LimitReader(f, maxBytes))
		_ = f.Close()
		if readErr != nil {
			continue
		}
		return name, string(buf)
	}
	return "", ""
}

// firstNonEmptyLine returns the first non-blank line of a license text,
// trimmed and bounded to 80 bytes. Used as a diagnostic hint when the
// classifier can't match a known SPDX.
func firstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if len(ln) > 80 {
			ln = ln[:80]
		}
		return ln
	}
	return ""
}

// loadWaivers parses `.license-waivers.txt`. Format:
//
//	# Justification line (required on the line immediately above)
//	github.com/example/module
//
// The justification is captured per-module and surfaced in the report so
// reviewers can see why each waiver exists.
func loadWaivers(path string) (map[string]string, error) {
	waivers := map[string]string{}
	f, err := os.Open(path) //#nosec G304 -- path is operator-supplied via -waivers flag (default .license-waivers.txt at repo root)
	if err != nil {
		if os.IsNotExist(err) {
			return waivers, nil // no file is fine
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	// pendingComment accumulates CONSECUTIVE comment lines (each
	// trimmed and "#"-stripped) immediately above a module path, so a
	// multi-line justification like:
	//   # Approved by legal
	//   # MPL-2.0 file-level copyleft does not apply (no upstream mods)
	//   some/module/path
	// is captured in full rather than only the last line. A blank line
	// resets the accumulator, so a stray comment further up in the
	// file does not bleed into an unrelated waiver below.
	var pendingComment []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			pendingComment = pendingComment[:0]
			continue
		}
		if strings.HasPrefix(line, "#") {
			pendingComment = append(pendingComment, strings.TrimSpace(strings.TrimPrefix(line, "#")))
			continue
		}
		// Module path (with optional inline comment).
		modPath := line
		if idx := strings.Index(line, "#"); idx >= 0 {
			modPath = strings.TrimSpace(line[:idx])
		}
		var justification string
		if len(pendingComment) > 0 {
			justification = strings.Join(pendingComment, " ")
		} else {
			justification = "(no justification recorded)"
		}
		waivers[modPath] = justification
		pendingComment = pendingComment[:0]
	}
	return waivers, scanner.Err()
}

// report prints a human-readable table to stdout and a summary count.
func report(findings []finding) {
	if len(findings) == 0 {
		fmt.Println("No third-party modules found.")
		return
	}

	var (
		allow, warn, deny, waivered, unknown int
	)
	for _, f := range findings {
		switch f.Class {
		case classAllow:
			allow++
		case classWarn:
			warn++
		case classDeny:
			deny++
		case classWaivered:
			waivered++
		case classUnknown:
			unknown++
		}
	}

	fmt.Printf("%-60s %-15s %-15s %-8s\n", "MODULE", "VERSION", "LICENSE", "CLASS")
	fmt.Println(strings.Repeat("-", 100))
	for _, f := range findings {
		lic := f.License
		if lic == "" {
			lic = "?"
		}
		fmt.Printf("%-60s %-15s %-15s %-8s\n", trunc(f.Module, 60), trunc(f.Version, 15), lic, f.Class)
		if f.Note != "" && (f.Class == classUnknown || f.Class == classDeny || f.Class == classWaivered) {
			fmt.Printf("  └─ %s\n", f.Note)
		}
	}
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("Summary: %d ALLOW, %d WARN, %d DENY, %d WAIVERED, %d UNKNOWN (total %d modules)\n",
		allow, warn, deny, waivered, unknown, len(findings))
}

// trunc returns s shortened to at most n display columns (runes), with
// a trailing ellipsis when truncation happens. We slice on rune
// boundaries rather than byte boundaries because (a) Go's fmt verbs
// `%-Ns` pad on rune width, so a byte-slice cut would mis-align the
// column when s contains multi-byte UTF-8, and (b) a byte slice can
// land in the middle of a multi-byte sequence producing invalid UTF-8
// in the report. Module paths and version strings are RFC-required
// ASCII so this is purely defensive, but cheap.
func trunc(s string, n int) string {
	if n <= 1 {
		return s
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}

// writeJSON serialises the findings list to a path.
func writeJSON(path string, findings []finding) error {
	type item struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		License string `json:"license"`
		Class   string `json:"class"`
		File    string `json:"license_file,omitempty"`
		Note    string `json:"note,omitempty"`
	}
	items := make([]item, len(findings))
	for i, f := range findings {
		items[i] = item{
			Module:  f.Module,
			Version: f.Version,
			License: f.License,
			Class:   f.Class.String(),
			File:    f.File,
			Note:    f.Note,
		}
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// writeCSV serialises the findings list as comma-separated values.
// Schema: module,version,license,class,file,note
func writeCSV(path string, findings []finding) error {
	var sb strings.Builder
	sb.WriteString("module,version,license,class,file,note\n")
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("%q,%q,%q,%q,%q,%q\n",
			f.Module, f.Version, f.License, f.Class.String(), f.File, f.Note))
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sn360-es-license-check: "+format+"\n", args...)
	os.Exit(1)
}
