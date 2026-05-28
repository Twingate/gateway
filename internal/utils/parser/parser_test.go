// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_New(t *testing.T) {
	tests := []struct {
		name         string
		variable     string
		wantPrefix   string
		wantVariable string
		wantSuffix   string
		wantErr      error
		errSubstr    string
	}{
		{
			name:       "plain text",
			variable:   "static-value",
			wantPrefix: "static-value",
		},
		{
			name:     "empty string",
			variable: "",
		},
		{
			name:         "single placeholder",
			variable:     "{{twingate.jwt}}",
			wantVariable: "jwt",
		},
		{
			name:         "Expression with leading and trailing space",
			variable:     "{{  twingate.jwt  }}",
			wantVariable: "jwt",
		},
		{
			name:         "Expression with prefix",
			variable:     " Bearer {{twingate.jwt}}",
			wantPrefix:   "Bearer ",
			wantVariable: "jwt",
		},
		{
			name:         "suffix after placeholder",
			variable:     "{{twingate.username}}/profile ",
			wantVariable: "username",
			wantSuffix:   "/profile",
		},
		{
			name:      "Invalid variable format",
			variable:  "{{invalid}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid variable syntax",
		},
		{
			name:      "Missing opening braces",
			variable:  "twingate.jwt }}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid variable syntax",
		},
		{
			name:      "Missing closing braces",
			variable:  "{{ twingate.jwt",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "invalid variable syntax",
		},
		{
			name:      "multiple variables rejected",
			variable:  "{{twingate.username}} {{twingate.groups}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "multiple variable are not supported",
		},
		{
			name:      "non-twingate namespace",
			variable:  "{{other.key}}",
			wantErr:   ErrInvalidTemplate,
			errSubstr: "unsupported namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := New(tt.variable)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Contains(t, err.Error(), tt.errSubstr)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.wantPrefix, template.prefix)
			assert.Equal(t, tt.wantVariable, template.variable)
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
			name:     "Success evaluate",
			template: Template{prefix: "Prefix ", variable: "foo", suffix: " suffix"},
			values:   map[string]string{"foo": "bar", "extra": "foo"},
			want:     "Prefix bar suffix",
		},
		{
			name:     "Success evaluate",
			template: Template{prefix: "Bearer ", variable: "jwt"},
			values:   map[string]string{"jwt": "test-token", "extra": "foo"},
			want:     "Bearer test-token",
		},
		{
			name:      "Missing variable",
			template:  Template{prefix: "Bearer ", variable: "jwt", suffix: ""},
			values:    map[string]string{},
			wantErr:   ErrUnknownVariable,
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
