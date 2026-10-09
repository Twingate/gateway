// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package yaml

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

const hoursPerDay = 24

var (
	errSizeTooLarge     = errors.New("size too large")
	errNegativeDuration = errors.New("duration must be non-negative")
)

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

// Duration is a time.Duration that also accepts a leading number of days, such as "7d", "1.5d" or "1d12h".
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	duration, err := parseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}

	if duration < 0 {
		return fmt.Errorf("%w: %q", errNegativeDuration, text)
	}

	*d = Duration(duration)

	return nil
}

// parseDuration extends time.ParseDuration with an optional leading days component, where a day is 24 hours.
func parseDuration(text string) (time.Duration, error) {
	days, rest, found := strings.Cut(text, "d")
	if !found {
		return time.ParseDuration(text)
	}

	count, err := strconv.ParseFloat(days, 64)
	if err != nil {
		return 0, err
	}

	hours := strconv.FormatFloat(count*hoursPerDay, 'f', -1, 64)

	return time.ParseDuration(hours + "h" + rest)
}
