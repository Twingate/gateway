// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package parser

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	allowedNamespace = "twingate"
)

var (
	ErrInvalidTemplate = errors.New("invalid template")
	ErrUnknownVariable = errors.New("unknown variable")
)

var templateRe = regexp.MustCompile(
	`^(.*?)` + // prefix
		`{{\s*` + // opening braces
		`([a-zA-Z0-9_-]+)` + // namespace
		`\.` +
		`([a-zA-Z0-9_-]+)` + // key
		`\s*}}` + // closing braces
		`(.*)$`, // suffix
)

type Template struct {
	prefix   string
	variable string
	suffix   string
}

func New(s string) (*Template, error) {
	match := templateRe.FindStringSubmatch(s)

	if match == nil {
		if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
			return nil, fmt.Errorf("%w: invalid variable syntax", ErrInvalidTemplate)
		}

		return &Template{prefix: s}, nil
	}

	prefix, namespace, variable, suffix := match[1], match[2], match[3], match[4]

	if namespace != allowedNamespace {
		return nil, fmt.Errorf("%w: unsupported namespace %q", ErrInvalidTemplate, namespace)
	}

	if templateRe.MatchString(suffix) {
		return nil, fmt.Errorf("%w: multiple variable are not supported", ErrInvalidTemplate)
	}

	return &Template{
		prefix:   strings.TrimLeftFunc(prefix, unicode.IsSpace),
		variable: variable,
		suffix:   strings.TrimRightFunc(suffix, unicode.IsSpace),
	}, nil
}

func (t *Template) Variable() string {
	return t.variable
}

func (t *Template) Evaluate(variables map[string]string) (string, error) {
	if t.variable == "" {
		return t.prefix, nil
	}

	result, ok := variables[t.variable]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownVariable, t.variable)
	}

	return t.prefix + result + t.suffix, nil
}
