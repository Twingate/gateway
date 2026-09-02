// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package useragent

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gateway/internal/version"
)

func TestString(t *testing.T) {
	original := version.Version

	t.Cleanup(func() { version.Version = original })

	version.Version = "1.2.3"

	assert.Equal(t, "Twingate-Gateway/1.2.3", String())
}
