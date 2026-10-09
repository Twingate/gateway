// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package yaml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestByteSize_UnmarshalText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		want        int
		errContains string
	}{
		{name: "binary unit", text: "1Mi", want: 1_048_576},
		{name: "binary unit long form", text: "1MiB", want: 1_048_576},
		{name: "decimal unit", text: "1M", want: 1_000_000},
		{name: "decimal unit long form", text: "1MB", want: 1_000_000},
		{name: "lowercase unit", text: "1mb", want: 1_000_000},
		{name: "no unit", text: "1000000", want: 1_000_000},
		{name: "zero", text: "0", want: 0},
		{name: "fraction of a unit", text: "1.5MB", want: 1_500_000},
		{name: "fraction of a byte rounds down", text: "0.5", want: 0},
		{name: "not a number", text: "large", errContains: "invalid size"},
		{name: "negative", text: "-1MB", errContains: "invalid size"},
		{name: "sub-byte unit", text: "1n", errContains: "invalid size"},
		{name: "too large", text: "10EB", errContains: "too large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var size ByteSize

			err := size.UnmarshalText([]byte(tt.text))
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, size.Bytes())
		})
	}
}

func TestDuration_UnmarshalText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		want        time.Duration
		errContains string
	}{
		{name: "go duration", text: "36h", want: 36 * time.Hour},
		{name: "days", text: "7d", want: 7 * 24 * time.Hour},
		{name: "fraction of a day", text: "1.5d", want: 36 * time.Hour},
		{name: "days followed by hours", text: "1d12h", want: 36 * time.Hour},
		{name: "zero", text: "0", want: 0},
		{name: "negative", text: "-1d", errContains: "must be non-negative"},
		{name: "infinite days", text: "infd", errContains: "invalid duration"},
		{name: "not a number of days", text: "nand", errContains: "invalid duration"},
		{name: "too many days", text: "1e300d", errContains: "invalid duration"},
		{name: "missing unit", text: "7", errContains: "invalid duration"},
		{name: "not a duration", text: "week", errContains: "invalid duration"},
		{name: "unit without a number", text: "d", errContains: "invalid duration"},
		{name: "days followed by garbage", text: "1dx", errContains: "invalid duration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var duration Duration

			err := duration.UnmarshalText([]byte(tt.text))
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, time.Duration(duration))
		})
	}
}
