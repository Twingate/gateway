// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package yaml

import (
	"errors"
	"fmt"
	"math"

	"github.com/dustin/go-humanize"
)

var errSizeTooLarge = errors.New("size too large")

type ByteSize int

func (b *ByteSize) UnmarshalText(text []byte) error {
	size, err := humanize.ParseBytes(string(text))
	if err != nil {
		return fmt.Errorf("invalid size %q: %w", text, err)
	}

	if size > math.MaxInt {
		return fmt.Errorf("%w: %q", errSizeTooLarge, text)
	}

	*b = ByteSize(size)

	return nil
}

func (b ByteSize) Bytes() int {
	return int(b)
}
