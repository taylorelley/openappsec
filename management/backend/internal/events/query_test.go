// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import (
	"strings"
	"testing"
)

func TestParseDocumentedExamples(t *testing.T) {
	// Straight from https://docs.openappsec.io/references/event-query-language
	cases := []string{
		`sourceip:192.168.2.1`,
		`practicetype:"Threat Prevention" AND securityaction:Prevent`,
		`sourceip:(192.168.2.1 OR 192.168.2.2)`,
		`assetname:juice-shop`,
		`sourceip:192.168.0.0/16`,
		`sourceip:192.168.*`,
		`NOT securityaction:Detect`,
		`waapincidenttype:"SQL Injection" AND NOT sourceip:10.0.0.1`,
	}
	for _, q := range cases {
		node, err := Parse(q)
		if err != nil {
			t.Errorf("Parse(%q) failed: %v", q, err)
			continue
		}
		if node == nil {
			t.Errorf("Parse(%q) returned nil node", q)
			continue
		}
		if _, _, err := Compile(node, 0); err != nil {
			t.Errorf("Compile(%q) failed: %v", q, err)
		}
	}
}

// The documentation states OR is applied before AND when parentheses are
// absent, which inverts the usual precedence.
func TestOrBindsTighterThanAnd(t *testing.T) {
	node, err := Parse(`a AND b OR c`)
	if err != nil {
		t.Fatal(err)
	}
	and, ok := node.(*AndNode)
	if !ok {
		t.Fatalf("expected top level AND, got %T", node)
	}
	if len(and.Children) != 2 {
		t.Fatalf("expected 2 AND children, got %d", len(and.Children))
	}
	if _, ok := and.Children[1].(*OrNode); !ok {
		t.Fatalf("expected second AND child to be an OR group, got %T", and.Children[1])
	}
}

func TestImplicitAnd(t *testing.T) {
	node, err := Parse(`securityaction:Prevent assetname:shop`)
	if err != nil {
		t.Fatal(err)
	}
	and, ok := node.(*AndNode)
	if !ok {
		t.Fatalf("juxtaposition should imply AND, got %T", node)
	}
	if len(and.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(and.Children))
	}
}

func TestParenthesesOverridePrecedence(t *testing.T) {
	node, err := Parse(`(a OR b) AND c`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := node.(*AndNode); !ok {
		t.Fatalf("expected AND at top level, got %T", node)
	}
}

func TestQuotedPhrase(t *testing.T) {
	node, err := Parse(`practicetype:"Threat Prevention"`)
	if err != nil {
		t.Fatal(err)
	}
	term, ok := node.(*TermNode)
	if !ok {
		t.Fatalf("expected term, got %T", node)
	}
	if term.Value != "Threat Prevention" {
		t.Fatalf("quoted phrase lost: %q", term.Value)
	}
}

func TestCIDRUsesInetContainment(t *testing.T) {
	node, _ := Parse(`sourceip:192.168.0.0/16`)
	sql, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "source_ip_addr <<=") {
		t.Fatalf("CIDR should compile to inet containment, got: %s", sql)
	}
	if len(args) != 1 || args[0] != "192.168.0.0/16" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestIPWildcardUsesLike(t *testing.T) {
	node, _ := Parse(`sourceip:192.168.*`)
	sql, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "source_ip ILIKE") {
		t.Fatalf("wildcard IP should compile to ILIKE, got: %s", sql)
	}
	if args[0] != "192.168.%" {
		t.Fatalf("wildcard not translated: %v", args[0])
	}
}

func TestWildcardTranslation(t *testing.T) {
	cases := map[string]string{
		"abc*":     "abc%",
		"a?c":      "a_c",
		"100%*":    `100\%%`,
		"under_*":  `under\_%`,
		`back\sl*`: `back\\sl%`,
	}
	for in, want := range cases {
		if got := wildcardToLike(in); got != want {
			t.Errorf("wildcardToLike(%q) = %q, want %q", in, got, want)
		}
	}
}

// Literal LIKE metacharacters must be escaped so a value containing '%' does
// not silently become a wildcard match.
func TestLikeMetacharactersAreEscaped(t *testing.T) {
	node, _ := Parse(`matchedsample:50%*`)
	_, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != `50\%%` {
		t.Fatalf("literal %% not escaped: %v", args[0])
	}
}

func TestExactMatchIsCaseInsensitive(t *testing.T) {
	node, _ := Parse(`securityaction:prevent`)
	sql, _, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "lower(security_action) = lower(") {
		t.Fatalf("expected case-insensitive comparison, got: %s", sql)
	}
}

func TestUnknownFieldIsRejected(t *testing.T) {
	node, err := Parse(`nosuchfield:value`)
	if err != nil {
		t.Fatalf("parse should succeed; validation happens at compile: %v", err)
	}
	if _, _, err := Compile(node, 0); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestFreeTextSearchesSeveralColumns(t *testing.T) {
	node, _ := Parse(`juice-shop`)
	sql, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "asset_name") || !strings.Contains(sql, "source_ip") {
		t.Fatalf("free text should span several columns, got: %s", sql)
	}
	if len(args) != len(freeTextColumns) {
		t.Fatalf("expected %d args, got %d", len(freeTextColumns), len(args))
	}
}

func TestPlaceholderOffset(t *testing.T) {
	node, _ := Parse(`assetname:a AND securityaction:b`)
	sql, args, err := Compile(node, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "$6") || !strings.Contains(sql, "$7") {
		t.Fatalf("placeholders should start after the offset, got: %s", sql)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
}

func TestParseErrors(t *testing.T) {
	for _, q := range []string{
		`assetname:`,
		`(assetname:a`,
		`"unterminated`,
		`sourceip:(a OR b`,
	} {
		if _, err := Parse(q); err == nil {
			t.Errorf("expected a parse error for %q", q)
		}
	}
}

func TestEmptyQueryMatchesEverything(t *testing.T) {
	node, err := Parse("   ")
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sql != "TRUE" || len(args) != 0 {
		t.Fatalf("empty query should match everything, got %q with %v", sql, args)
	}
}

// No user-supplied text may reach the SQL string; everything must be bound.
func TestValuesAreAlwaysParameterised(t *testing.T) {
	node, err := Parse(`assetname:"'; DROP TABLE events; --"`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := Compile(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("value was interpolated into SQL: %s", sql)
	}
	if len(args) != 1 || args[0] != `'; DROP TABLE events; --` {
		t.Fatalf("value should be bound verbatim, got %v", args)
	}
}
