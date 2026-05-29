package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// classifyText is the unit-test entrypoint into the matcher: it mirrors
// the title-head + full-text bisection from classifyModule.
func classifyText(licenseText string) (string, classification) {
	normalised := strings.ToLower(licenseText)
	head := normalised
	if len(head) > titleHeadBytes {
		head = head[:titleHeadBytes]
	}
	for _, r := range rules {
		if matchesRule(normalised, head, r) {
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
