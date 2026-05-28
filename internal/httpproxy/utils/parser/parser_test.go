// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_NewTemplate(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPrefix string
		wantKey    string
		wantSuffix string
		wantErr    error
		errSubstr  string
	}{
		{
			name:       "plain text",
			input:      "static-value",
			wantPrefix: "static-value",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:    "single placeholder",
			input:   "{{twingate.jwt}}",
			wantKey: "jwt",
		},
		{
			name:    "template with leading and trailing space",
			input:   "{{  twingate.jwt  }}",
			wantKey: "jwt",
		},
		{
			name:       "template with prefix",
			input:      " Bearer {{twingate.jwt}}",
			wantPrefix: "Bearer ",
			wantKey:    "jwt",
		},
		{
			name:       "suffix after placeholder",
			input:      "{{twingate.username}}/profile ",
			wantKey:    "username",
			wantSuffix: "/profile",
		},
		{
			name:      "Invalid template format",
			input:     "{{invalid}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid brackets syntax",
		},
		{
			name:      "Missing opening braces",
			input:     "twingate.jwt }}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid brackets syntax",
		},
		{
			name:      "Missing closing braces",
			input:     "{{ twingate.jwt",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid brackets syntax",
		},
		{
			name:      "multiple templates rejected",
			input:     "{{twingate.username}} {{twingate.groups}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "multiple templates are not supported",
		},
		{
			name:      "non-twingate namespace",
			input:     "{{other.key}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := NewTemplate(tt.input)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Contains(t, err.Error(), tt.errSubstr)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.wantPrefix, template.prefix)
			assert.Equal(t, tt.wantKey, template.key)
			assert.Equal(t, tt.wantSuffix, template.suffix)
		})
	}
}

func TestParser_Evaluate(t *testing.T) {
	tests := []struct {
		name      string
		template  Template
		values    map[string]string
		want      string
		wantErr   error
		errSubstr string
	}{
		{
			name:     "Success",
			template: Template{prefix: "Prefix ", key: "foo", suffix: " suffix"},
			values:   map[string]string{"foo": "bar", "extra": "foo"},
			want:     "Prefix bar suffix",
		},
		{
			name:      "Missing key",
			template:  Template{prefix: "Bearer ", key: "jwt", suffix: ""},
			values:    map[string]string{},
			wantErr:   ErrUnknownKey,
			errSubstr: "jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.template.Evaluate(tt.values)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Contains(t, err.Error(), tt.errSubstr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}
