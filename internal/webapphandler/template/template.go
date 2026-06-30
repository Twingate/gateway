// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	JWT           = "jwt"
	Username      = "username"
	Groups        = "groups"
	ClientLatLong = "clientLatLong"
	ClientCity    = "clientCity"
	ClientRegion  = "clientRegion"
	ClientCountry = "clientCountry"
)

var AllowedWebAppKeys = []string{
	JWT,
	Username,
	Groups,
	ClientLatLong,
	ClientCity,
	ClientRegion,
	ClientCountry,
}

var (
	ErrInvalidTemplate = errors.New("invalid template")
	ErrUnknownKey      = errors.New("unknown key")
	ErrUnsupportedKey  = errors.New("unsupported key")
)

var templateRe = regexp.MustCompile(
	`^([^{}]*)` + // prefix (no braces allowed)
		`{{\s*` + // opening braces
		`([a-zA-Z0-9_-]+)` + // key
		`\s*}}` + // closing braces
		`([^{}]*)$`, // suffix (no braces allowed)
)

type Template struct {
	prefix string
	key    string
	suffix string
}

// New parses a string like "<prefix> {{<key>}} <suffix>" into a Template.
// If there is no template variable (just a static string), the key and suffix are empty and the prefix is the static string.
func New(s string) (*Template, error) {
	match := templateRe.FindStringSubmatch(s)

	if match == nil {
		if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
			return nil, fmt.Errorf("%w: unsupported syntax. Syntax must be <prefix> {{key}} <suffix>", ErrInvalidTemplate)
		}

		return &Template{prefix: strings.TrimSpace(s)}, nil
	}

	prefix, key, suffix := match[1], match[2], match[3]

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
