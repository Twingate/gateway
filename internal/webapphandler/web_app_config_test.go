// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"gateway/internal/httpproxy/utils/parser"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr error
	}{
		{
			name: "valid header templates",
			headers: map[string]string{
				"Authorization": "Bearer {{twingate.jwt}}",
			},
		},
		{
			name: "invalid template syntax",
			headers: map[string]string{
				"X-Invalid": "{{invalid}}",
			},
			wantErr: parser.ErrInvalidTemplate,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
		},
		{
			name:    "nil headers",
			headers: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(tt.headers, nil, zap.NewNop())

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
		})
	}
}
