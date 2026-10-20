// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecorder

import "unicode/utf8"

const hexDigits = "0123456789abcdef"

// appendJSONString appends src to dst as a quoted JSON string, producing the same bytes as
// json.Marshal(string(src)): HTML characters are escaped, invalid UTF-8 is replaced with
// U+FFFD, and U+2028 and U+2029 are escaped.
func appendJSONString(dst, src []byte) []byte {
	dst = append(dst, '"')
	start := 0

	for i := 0; i < len(src); {
		if b := src[i]; b < utf8.RuneSelf {
			if isJSONSafe(b) {
				i++

				continue
			}

			dst = append(dst, src[start:i]...)

			switch b {
			case '\\', '"':
				dst = append(dst, '\\', b)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				// Other control characters and the HTML characters <, > and &.
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}

			i++
			start = i

			continue
		}

		c, size := utf8.DecodeRune(src[i:])

		switch {
		case c == utf8.RuneError && size == 1:
			dst = append(dst, src[start:i]...)
			dst = append(dst, `�`...)
		case c == ' ' || c == ' ':
			dst = append(dst, src[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[c&0xF])
		default:
			i += size

			continue
		}

		i += size
		start = i
	}

	dst = append(dst, src[start:]...)

	return append(dst, '"')
}

// isJSONSafe reports whether the ASCII byte b can appear unescaped in a JSON string that
// json.Marshal produces.
func isJSONSafe(b byte) bool {
	return b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&'
}
