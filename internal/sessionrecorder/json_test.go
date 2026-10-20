// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecorder

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var jsonStringCases = []struct {
	name  string
	input string
}{
	{name: "empty", input: ""},
	{name: "plain ASCII", input: "hello world"},
	{name: "quotes and backslashes", input: `say "hi" \ bye`},
	{name: "short escapes", input: "\b\f\n\r\t"},
	{name: "other control characters", input: "\x00\x01\x1b[32mgreen\x1b[0m\x7f"},
	{name: "HTML characters", input: "<script>a && b</script>"},
	{name: "multi-byte UTF-8", input: "héllo 世界 🚀"},
	{name: "line and paragraph separators", input: "a b c"},
	{name: "invalid UTF-8", input: "a\xffb\xc3"},
	{name: "truncated multi-byte rune", input: "\xe4\xb8"},
}

func TestAppendJSONString(t *testing.T) {
	for _, tt := range jsonStringCases {
		t.Run(tt.name, func(t *testing.T) {
			want, err := json.Marshal(tt.input)
			require.NoError(t, err)

			assert.Equal(t, string(want), string(appendJSONString(nil, []byte(tt.input))))
		})
	}
}

func TestAppendJSONString_AppendsToDst(t *testing.T) {
	assert.Equal(t, `prefix:"a\nb"`, string(appendJSONString([]byte("prefix:"), []byte("a\nb"))))
}

func FuzzAppendJSONString(f *testing.F) {
	for _, tt := range jsonStringCases {
		f.Add([]byte(tt.input))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		want, err := json.Marshal(string(input))
		require.NoError(t, err)

		assert.Equal(t, string(want), string(appendJSONString(nil, input)))
	})
}
