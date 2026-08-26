// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package useragent

import (
	"net/http"

	"gateway/internal/version"
)

// String returns the User-Agent identifying this build in outbound HTTP requests.
func String() string {
	return "Twingate-Gateway/" + version.Version
}

type Transport struct {
	// Base is the transport the request is handed to. If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", String())

	return base.RoundTrip(req)
}
