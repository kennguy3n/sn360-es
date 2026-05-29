package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// classifyText is the unit-test entrypoint into the matcher: it mirrors
// the title-head bisection from classifyModule.
func classifyText(licenseText string) (string, classification) {
	normalised := strings.ToLower(licenseText)
	head := normalised
	if len(head) > titleHeadBytes {
		head = head[:titleHeadBytes]
	}
	for _, r := range rules {
		if matchesRule(head, r) {
			return r.SPDX, r.class
		}
	}
	return "", classUnknown
}

func TestClassify_MIT(t *testing.T) {
	const mitText = `MIT License

Copyright (c) 2024 Example Corp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.`

	spdx, class := classifyText(mitText)
	if spdx != "MIT" || class != classAllow {
		t.Fatalf("expected MIT/ALLOW, got %s/%s", spdx, class)
	}
}

func TestClassify_Apache2(t *testing.T) {
	const apacheText = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.`

	spdx, class := classifyText(apacheText)
	if spdx != "Apache-2.0" || class != classAllow {
		t.Fatalf("expected Apache-2.0/ALLOW, got %s/%s", spdx, class)
	}
}

func TestClassify_BSD3Clause(t *testing.T) {
	const bsd3 = `Copyright (c) 2024 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.`

	spdx, class := classifyText(bsd3)
	if spdx != "BSD-3-Clause" || class != classAllow {
		t.Fatalf("expected BSD-3-Clause/ALLOW, got %s/%s", spdx, class)
	}
}

func TestClassify_BSD2Clause(t *testing.T) {
	const bsd2 = `Copyright (c) 2024 Example. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.`

	spdx, class := classifyText(bsd2)
	if spdx != "BSD-2-Clause" || class != classAllow {
		t.Fatalf("expected BSD-2-Clause/ALLOW, got %s/%s", spdx, class)
	}
}

func TestClassify_ISC(t *testing.T) {
	const isc = `ISC License

Copyright (c) 2024 Example

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.`

	spdx, class := classifyText(isc)
	if spdx != "ISC" || class != classAllow {
		t.Fatalf("expected ISC/ALLOW, got %s/%s", spdx, class)
	}
}

func TestClassify_MPL2(t *testing.T) {
	const mpl2 = `Mozilla Public License Version 2.0
==================================

1. Definitions
--------------

1.1. "Contributor"
    means each individual or legal entity that creates, contributes to
    the creation of, or owns Covered Software.`

	spdx, class := classifyText(mpl2)
	if spdx != "MPL-2.0" || class != classAllow {
		t.Fatalf("expected MPL-2.0/ALLOW, got %s/%s", spdx, class)
	}
}

// TestClassify_MPL2_WithLGPLCompatClause is the regression test for the
// pgregory.net/rapid false-positive: MPL-2.0's §3.3 references "Lesser
// General Public License" by name, but the rule should still resolve
// to MPL-2.0 (not LGPL) because the LGPL phrase appears in the body,
// not the title head.
func TestClassify_MPL2_WithLGPLCompatClause(t *testing.T) {
	mpl2 := strings.Repeat("Mozilla Public License Version 2.0\n", 5) +
		strings.Repeat("filler boilerplate that takes up space ", 60) + "\n" +
		// Position the LGPL mention well past titleHeadBytes (2000).
		strings.Repeat("more filler to push the LGPL mention past 2 KB ", 30) +
		"\n3.3. Distribution of a Larger Work\n\nYou may create and distribute a Larger Work under terms of Your choice, provided that You also comply with the requirements of this License for the Covered Software. ... If the Larger Work is a combination of Covered Software with a work governed by one or more Secondary Licenses, You may distribute such combination under the terms of the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero General Public License, Version 3.0, or any later versions of those licenses.\n"

	spdx, class := classifyText(mpl2)
	if spdx != "MPL-2.0" || class != classAllow {
		t.Fatalf("expected MPL-2.0/ALLOW (compat clause must not trip LGPL), got %s/%s", spdx, class)
	}
}

func TestClassify_LGPL3(t *testing.T) {
	const lgpl = `                   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc.
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

  This version of the GNU Lesser General Public License incorporates
the terms and conditions of version 3 of the GNU General Public
License, supplemented by the additional permissions listed below.`

	spdx, class := classifyText(lgpl)
	if spdx != "LGPL-3.0" || class != classDeny {
		t.Fatalf("expected LGPL-3.0/DENY, got %s/%s", spdx, class)
	}
}

func TestClassify_GPL3(t *testing.T) {
	const gpl3 = `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc.
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.`

	spdx, class := classifyText(gpl3)
	if spdx != "GPL-3.0" || class != classDeny {
		t.Fatalf("expected GPL-3.0/DENY, got %s/%s", spdx, class)
	}
}

// TestClassify_GPL3_WithCanonicalAppendix is the regression test for the
// bug where the GPL-3.0 rule's `mustNotContain: ["lesser general public
// license"]` previously scanned the FULL file text. The canonical
// GPL-3.0 license is ~35 KiB and ends with a “How to Apply” appendix
// containing the line:
//
//	If the program does terminal interaction, […] we recommend
//	that you use the GNU Lesser General Public License instead
//	of this License.
//
// Under the pre-fix scope (mustNotContain over the entire file), that
// mention tripped the exclusion and bounced the GPL-3.0 rule, causing
// a real GPL-3.0 module to fall through to classUnknown instead of
// classDeny. The fix scopes mustNotContain to the title head (the
// same window as mustContain), where the LGPL/AGPL exclusions belong
// because they are the title-level differentiator for those families.
func TestClassify_GPL3_WithCanonicalAppendix(t *testing.T) {
	// Build a realistic 35 KiB-ish GPL-3.0 text: title head + bulk
	// filler + the canonical appendix paragraph that mentions LGPL.
	var sb strings.Builder
	sb.WriteString(`                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.
`)
	// ~32 KiB of body filler that does NOT mention LGPL/AGPL — this
	// guarantees the title head (first 2 KiB) is the original GPL-3.0
	// boilerplate and the LGPL mention only lives in the appendix.
	sb.WriteString(strings.Repeat("The terms and conditions of redistribution and modification follow. ", 500))
	sb.WriteString(`\n                     END OF TERMS AND CONDITIONS\n
            How to Apply These Terms to Your New Programs\n\n
  If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:\n\n
  The hypothetical commands 'show w' and 'show c' should show the
appropriate parts of the General Public License. Of course, your
program's commands might be different; for a GUI interface, you would
use an "about box".\n\n
  You should also get your employer (if you work as a programmer) or
school, if any, to sign a "copyright disclaimer" for the program, if
necessary. For more information on this, and how to apply and follow
the GNU GPL, see <https://www.gnu.org/licenses/>.\n\n
  The GNU General Public License does not permit incorporating your
program into proprietary programs. If your program is a subroutine
library, you may consider it more useful to permit linking proprietary
applications with the library. If this is what you want to do, use
the GNU Lesser General Public License instead of this License. But
first, please read <https://www.gnu.org/licenses/why-not-lgpl.html>.\n
`)
	gpl3 := sb.String()

	if len(gpl3) <= titleHeadBytes {
		t.Fatalf("setup error: synthetic GPL-3.0 must exceed titleHeadBytes (%d), got %d", titleHeadBytes, len(gpl3))
	}
	// Sanity-check: the LGPL mention must live past the title head.
	appendixIdx := strings.Index(strings.ToLower(gpl3), "lesser general public license")
	if appendixIdx < titleHeadBytes {
		t.Fatalf("setup error: LGPL mention at offset %d should be past titleHeadBytes %d", appendixIdx, titleHeadBytes)
	}

	spdx, class := classifyText(gpl3)
	if spdx != "GPL-3.0" || class != classDeny {
		t.Fatalf("canonical GPL-3.0 with appendix must classify as GPL-3.0/DENY, got %s/%s \u2014 the mustNotContain scope must be the title head, not the full text", spdx, class)
	}
}

func TestClassify_AGPL3(t *testing.T) {
	const agpl = `                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc.

  The GNU Affero General Public License is a free, copyleft license for
software and other kinds of works, specifically designed to ensure
cooperation with the community in the case of network server software.`

	spdx, class := classifyText(agpl)
	if spdx != "AGPL-3.0" || class != classDeny {
		t.Fatalf("expected AGPL-3.0/DENY, got %s/%s", spdx, class)
	}
}

func TestClassify_SSPL(t *testing.T) {
	const sspl = `                   Server Side Public License
                       VERSION 1, October 16, 2018

Copyright (C) 2018 MongoDB, Inc.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.`

	spdx, class := classifyText(sspl)
	if spdx != "SSPL" || class != classDeny {
		t.Fatalf("expected SSPL/DENY, got %s/%s", spdx, class)
	}
}

func TestClassify_BUSL(t *testing.T) {
	const busl = `Business Source License 1.1

License text copyright (c) 2017 MariaDB Corporation Ab, All Rights Reserved.
"Business Source License" is a trademark of MariaDB Corporation Ab.`

	spdx, class := classifyText(busl)
	if spdx != "BUSL-1.1" || class != classDeny {
		t.Fatalf("expected BUSL-1.1/DENY, got %s/%s", spdx, class)
	}
}

func TestClassify_Unknown_EmptyText(t *testing.T) {
	spdx, class := classifyText("")
	if class != classUnknown {
		t.Fatalf("expected UNKNOWN for empty text, got %s/%s", spdx, class)
	}
}

func TestClassify_Unknown_UnrecognisedLicense(t *testing.T) {
	const obscure = `Some Company Custom License

This software is provided exclusively to authorized customers under
the terms of a separate commercial agreement.`

	spdx, class := classifyText(obscure)
	if class != classUnknown {
		t.Fatalf("expected UNKNOWN for unrecognised license, got %s/%s", spdx, class)
	}
}

// TestClassifyModule_WaiveredNoLicenseFile pins the new classWaivered
// branch: a module with no LICENSE file but listed in the waiver map
// must come back as WAIVERED (not UNKNOWN) so the report and exit
// logic can distinguish operator-accepted modules from genuine
// supply-chain risks.
func TestClassifyModule_WaiveredNoLicenseFile(t *testing.T) {
	dir := t.TempDir() // empty directory — no LICENSE file inside
	m := module{Path: "github.com/example/proprietary", Version: "v1.0.0", Dir: dir}
	waivers := map[string]string{"github.com/example/proprietary": "approved by legal team"}

	f := classifyModule(m, waivers)
	if f.Class != classWaivered {
		t.Fatalf("expected classWaivered, got %s (note=%q)", f.Class, f.Note)
	}
	if !strings.Contains(f.Note, "approved by legal team") {
		t.Errorf("waiver justification must surface in Note, got %q", f.Note)
	}
}

// TestClassifyModule_WaiveredNoRuleMatched mirrors the above for the
// other waivered path: a module that DOES have a LICENSE file but the
// text doesn't match any rule. Without a waiver it would be UNKNOWN;
// with a waiver it must come back WAIVERED.
func TestClassifyModule_WaiveredNoRuleMatched(t *testing.T) {
	dir := t.TempDir()
	licensePath := filepath.Join(dir, "LICENSE")
	const obscure = "Acme Custom License v0.1\n\nThis software is licensed exclusively under a private contract."
	if err := os.WriteFile(licensePath, []byte(obscure), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := module{Path: "acme.example/private", Version: "v0.1.0", Dir: dir}
	waivers := map[string]string{"acme.example/private": "vendored from internal repo"}

	f := classifyModule(m, waivers)
	if f.Class != classWaivered {
		t.Fatalf("expected classWaivered for waivered-and-unmatched module, got %s (note=%q)", f.Class, f.Note)
	}
	if !strings.Contains(f.Note, "vendored from internal repo") {
		t.Errorf("waiver justification must surface in Note, got %q", f.Note)
	}
}

// TestClassifyModule_UnknownNotWaivered exercises the failure branch:
// a module with no LICENSE file and no waiver must remain UNKNOWN so
// the strict-mode exit-code logic fails the build.
func TestClassifyModule_UnknownNotWaivered(t *testing.T) {
	dir := t.TempDir()
	m := module{Path: "github.com/unknown/thing", Version: "v1.0.0", Dir: dir}

	f := classifyModule(m, nil)
	if f.Class != classUnknown {
		t.Fatalf("expected classUnknown for non-waivered no-LICENSE module, got %s", f.Class)
	}
}

func TestLoadWaivers_FromFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waivers.txt")
	const content = `# Top-of-file comment is dropped
# Justification A: explicitly approved by legal team
github.com/example/proprietary-but-allowed

# Inline comment after module path
github.com/example/another-waivered  # with trailing comment

# Justification with no module path below it is also dropped`

	if err := writeTempFile(path, content); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	waivers, err := loadWaivers(path)
	if err != nil {
		t.Fatalf("loadWaivers: %v", err)
	}

	if len(waivers) != 2 {
		t.Errorf("expected 2 waivers, got %d: %v", len(waivers), waivers)
	}
	if j, ok := waivers["github.com/example/proprietary-but-allowed"]; !ok || !strings.Contains(j, "approved by legal team") {
		t.Errorf("missing or wrong justification for proprietary-but-allowed: %q (ok=%v)", j, ok)
	}
	if j, ok := waivers["github.com/example/another-waivered"]; !ok {
		t.Errorf("missing waiver for another-waivered (justification: %q, ok=%v)", j, ok)
	}
}

func TestLoadWaivers_MissingFile(t *testing.T) {
	// A missing waiver file is fine — empty map.
	waivers, err := loadWaivers("/nonexistent/path/to/waivers.txt")
	if err != nil {
		t.Fatalf("loadWaivers should return empty map on missing file, got error: %v", err)
	}
	if len(waivers) != 0 {
		t.Errorf("expected empty waivers, got %d", len(waivers))
	}
}

func TestFirstNonEmptyLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"\n\n  \n", ""},
		{"first\nsecond", "first"},
		{"  \n  with leading whitespace  \nthird", "with leading whitespace"},
		{strings.Repeat("a", 100), strings.Repeat("a", 80)},
	}
	for i, c := range cases {
		got := firstNonEmptyLine(c.in)
		if got != c.want {
			t.Errorf("case %d: firstNonEmptyLine(%q) = %q, want %q", i, c.in, got, c.want)
		}
	}
}

// writeTempFile is a thin wrapper around os.WriteFile used by the
// waiver-loader test.
func writeTempFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
