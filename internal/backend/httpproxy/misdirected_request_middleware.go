// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package httpproxy

import (
	"net/http"
	"net/url"
	"strings"
)

// misdirectedRequestMiddleware answers 421 to a request whose hostname does not resolve to the
// same upstream host of the connection's resource as the CONNECT host.
//
// An HTTP/2 client reuses a connection for any hostname that resolves to the same address and is
// covered by the server certificate, so a request can arrive on a connection authenticated for
// another resource. 421 makes the client retry on a connection of its own. The request hostname
// may differ from the CONNECT host (e.g. an alias vs the resource address), so the check is that
// both resolve to the same upstream host.
func misdirectedRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := ProxyConnFromContext(r.Context())
		requestHostname := (&url.URL{Host: r.Host}).Hostname()

		requestUpstreamHost, ok := conn.Claims.Resource.ResolveUpstreamHost(requestHostname)
		connUpstreamHost, _ := conn.Claims.Resource.ResolveUpstreamHost(conn.GetRequestedHost())

		if !ok || !strings.EqualFold(requestUpstreamHost, connUpstreamHost) {
			http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)

			return
		}

		next.ServeHTTP(w, r)
	})
}
