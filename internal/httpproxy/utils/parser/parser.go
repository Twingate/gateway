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
	ErrUnknownKey      = errors.New("unknown key")
)

var templateRe = regexp.MustCompile(
	`^([^{}]*)` + // prefix (no brackets allowed)
		`{{\s*` + // opening braces
		`([a-zA-Z0-9_-]+)` + // namespace
		`\.` +
		`([a-zA-Z0-9_-]+)` + // key
		`\s*}}` + // closing braces
		`([^{}]*)$`, // suffix (no brackets allowed)
)

type Template struct {
	prefix string
	key    string
	suffix string
}

// NewTemplate parses a string like "<prefix> {{<namespace>.<key>}} <suffix>" into a Template.
func NewTemplate(s string) (*Template, error) {
	match := templateRe.FindStringSubmatch(s)

	if match == nil {
		if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
			return nil, fmt.Errorf("%w: unsupported syntax. Syntax must be <prefix> {{twingate.key}} <suffix>", ErrInvalidTemplate)
		}

		return &Template{prefix: s}, nil
	}

	prefix, namespace, key, suffix := match[1], match[2], match[3], match[4]

	if namespace != allowedNamespace {
		return nil, fmt.Errorf("%w: unsupported namespace %q", ErrInvalidTemplate, namespace)
	}

	return &Template{
		prefix: strings.TrimLeftFunc(prefix, unicode.IsSpace),
		key:    key,
		suffix: strings.TrimRightFunc(suffix, unicode.IsSpace),
	}, nil
}

func (t *Template) Key() string {
	return t.key
}

// Evaluate replaces the key in the template with the corresponding value from the map
// and returns the resulting string along with the prefix and suffix.
func (t *Template) Evaluate(values map[string]string) (string, error) {
	if t.key == "" {
		return t.prefix, nil
	}

	result, ok := values[t.key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKey, t.key)
	}

	return t.prefix + result + t.suffix, nil
}
