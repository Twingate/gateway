// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package template

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
			input:      " static-value ",
			wantPrefix: "static-value",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:    "template only",
			input:   "{{jwt}}",
			wantKey: "jwt",
		},
		{
			name:    "client location template",
			input:   "{{clientCity}}",
			wantKey: "clientCity",
		},
		{
			name:    "template with leading and trailing space",
			input:   "{{  jwt  }}",
			wantKey: "jwt",
		},
		{
			name:       "template with prefix",
			input:      " Bearer {{jwt}}",
			wantPrefix: "Bearer ",
			wantKey:    "jwt",
		},
		{
			name:       "template with suffix",
			input:      "{{username}}/profile ",
			wantKey:    "username",
			wantSuffix: "/profile",
		},
		{
			name:      "missing opening braces",
			input:     "jwt }}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported syntax",
		},
		{
			name:      "missing closing braces",
			input:     "{{ jwt",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported syntax",
		},
		{
			name:      "multiple templates",
			input:     "{{username}} {{groups}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported syntax",
		},
		{
			name:      "namespaced syntax no longer supported",
			input:     "{{twingate.jwt}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := New(tt.input)

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
