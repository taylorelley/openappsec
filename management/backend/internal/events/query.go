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

// Package events implements search over ingested security events, including
// the Event Query Language documented at
// https://docs.openappsec.io/references/event-query-language.
package events

import (
	"fmt"
	"strings"
	"unicode"
)

// Node is a parsed query expression.
type Node interface{ node() }

type AndNode struct{ Children []Node }
type OrNode struct{ Children []Node }
type NotNode struct{ Child Node }

// TermNode is a single `field:value` criterion, or a bare value when Field is
// empty (a free-text search across the common columns).
type TermNode struct {
	Field string
	Value string
}

func (*AndNode) node()  {}
func (*OrNode) node()   {}
func (*NotNode) node()  {}
func (*TermNode) node() {}

// ---------------------------------------------------------------- tokenizer

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokQuoted
	tokLParen
	tokRParen
	tokColon
	tokAnd
	tokOr
	tokNot
)

type token struct {
	kind tokenKind
	text string
}

func tokenize(input string) ([]token, error) {
	var toks []token
	runes := []rune(input)

	for i := 0; i < len(runes); {
		c := runes[i]

		switch {
		case unicode.IsSpace(c):
			i++
			continue

		case c == '(':
			toks = append(toks, token{kind: tokLParen})
			i++

		case c == ')':
			toks = append(toks, token{kind: tokRParen})
			i++

		case c == ':':
			toks = append(toks, token{kind: tokColon})
			i++

		case c == '"' || c == '\'':
			quote := c
			i++
			start := i
			var sb strings.Builder
			for i < len(runes) && runes[i] != quote {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
				}
				sb.WriteRune(runes[i])
				i++
			}
			if i >= len(runes) {
				return nil, fmt.Errorf("unterminated quote starting at position %d", start)
			}
			i++ // closing quote
			toks = append(toks, token{kind: tokQuoted, text: sb.String()})

		default:
			start := i
			for i < len(runes) && !unicode.IsSpace(runes[i]) &&
				runes[i] != '(' && runes[i] != ')' && runes[i] != ':' &&
				runes[i] != '"' && runes[i] != '\'' {
				i++
			}
			word := string(runes[start:i])
			switch strings.ToUpper(word) {
			case "AND":
				toks = append(toks, token{kind: tokAnd})
			case "OR":
				toks = append(toks, token{kind: tokOr})
			case "NOT":
				toks = append(toks, token{kind: tokNot})
			default:
				toks = append(toks, token{kind: tokWord, text: word})
			}
		}
	}

	return append(toks, token{kind: tokEOF}), nil
}

// ------------------------------------------------------------------ parser

type parser struct {
	toks []token
	pos  int
}

// Parse turns an Event Query Language string into an expression tree.
//
// Precedence follows the documentation: "OR is applied before AND when
// parentheses aren't used", so OR binds tighter than AND — the opposite of the
// usual convention, and the reason this is hand-written rather than lifted
// from a generic expression parser.
func Parse(input string) (Node, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	toks, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}

	node, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected trailing input in query")
	}
	return node, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) accept(k tokenKind) bool {
	if p.peek().kind == k {
		p.pos++
		return true
	}
	return false
}

func (p *parser) parseAnd() (Node, error) {
	var children []Node
	for {
		child, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		children = append(children, child)

		// An explicit AND, or juxtaposition, continues the conjunction.
		if p.accept(tokAnd) {
			continue
		}
		switch p.peek().kind {
		case tokWord, tokQuoted, tokLParen, tokNot:
			continue
		}
		break
	}
	if len(children) == 1 {
		return children[0], nil
	}
	return &AndNode{Children: children}, nil
}

func (p *parser) parseOr() (Node, error) {
	first, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokOr {
		return first, nil
	}

	children := []Node{first}
	for p.accept(tokOr) {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return &OrNode{Children: children}, nil
}

func (p *parser) parseUnary() (Node, error) {
	if p.accept(tokNot) {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	switch t := p.peek(); t.kind {
	case tokLParen:
		p.next()
		inner, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		if !p.accept(tokRParen) {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return inner, nil

	case tokWord, tokQuoted:
		p.next()
		// `field:` introduces a criterion; a bare value is free text.
		if p.peek().kind == tokColon && t.kind == tokWord {
			p.next()
			return p.parseFieldValue(t.text)
		}
		return &TermNode{Value: t.text}, nil

	default:
		return nil, fmt.Errorf("unexpected token in query")
	}
}

// parseFieldValue handles both `field:value` and the grouped form
// `field:(a OR b)`, which the documentation gives as
// `sourceip:(192.168.2.1 OR 192.168.2.2)`.
func (p *parser) parseFieldValue(field string) (Node, error) {
	if p.accept(tokLParen) {
		node, err := p.parseGroupedValues(field)
		if err != nil {
			return nil, err
		}
		if !p.accept(tokRParen) {
			return nil, fmt.Errorf("missing closing parenthesis in value list for %q", field)
		}
		return node, nil
	}

	switch t := p.peek(); t.kind {
	case tokWord, tokQuoted:
		p.next()
		return &TermNode{Field: field, Value: t.text}, nil
	default:
		return nil, fmt.Errorf("missing value for field %q", field)
	}
}

func (p *parser) parseGroupedValues(field string) (Node, error) {
	var (
		children []Node
		isAnd    bool
	)
	for {
		if p.accept(tokNot) {
			inner, err := p.parseGroupedSingle(field)
			if err != nil {
				return nil, err
			}
			children = append(children, &NotNode{Child: inner})
		} else {
			inner, err := p.parseGroupedSingle(field)
			if err != nil {
				return nil, err
			}
			children = append(children, inner)
		}

		if p.accept(tokOr) {
			continue
		}
		if p.accept(tokAnd) {
			isAnd = true
			continue
		}
		if p.peek().kind == tokWord || p.peek().kind == tokQuoted {
			continue // juxtaposition inside a value list reads as OR
		}
		break
	}

	if len(children) == 1 {
		return children[0], nil
	}
	if isAnd {
		return &AndNode{Children: children}, nil
	}
	return &OrNode{Children: children}, nil
}

func (p *parser) parseGroupedSingle(field string) (Node, error) {
	switch t := p.peek(); t.kind {
	case tokWord, tokQuoted:
		p.next()
		return &TermNode{Field: field, Value: t.text}, nil
	default:
		return nil, fmt.Errorf("malformed value list for field %q", field)
	}
}
