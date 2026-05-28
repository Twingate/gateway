// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/metrics"
	"gateway/internal/token"
	"gateway/internal/utils/parser"
)

type Handler struct {
	proxy http.Handler
}

func NewHandler(cfg Config) *Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn := httpproxy.ProxyConnFromContext(r.In.Context())

			if err := rewrite(r, conn, cfg.headers); err != nil {
				cfg.logger.Error("failed to rewrite headers", zap.Error(err))
			}
		},
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperMetrics, "webapp", http.DefaultTransport),
	}

	return &Handler{proxy: proxy}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

func rewrite(r *httputil.ProxyRequest, conn *connect.ProxyConn, headers map[string]*parser.Template) error {
	targetURL := &url.URL{
		Scheme: "http", // plain HTTP — no upstream TLS
		Host:   conn.GetAddress(),
	}
	r.SetURL(targetURL)

	claims := conn.GATClaims()

	geoLoc := ""
	if claims.Device.Location != (token.DeviceLocation{}) {
		geoLoc = fmt.Sprintf("%v,%v", claims.Device.Location.GeoIP.Lat, claims.Device.Location.GeoIP.Lon)
	}

	variables := map[string]string{
		"jwt":          conn.GetToken(),
		"username":     claims.User.Username,
		"groups":       strings.Join(claims.User.Groups, ","),
		"clientGeoLoc": geoLoc,
	}

	for headerName, template := range headers {
		headerValue, err := template.Evaluate(variables)
		if err != nil {
			return fmt.Errorf("header %q: %w", headerName, err)
		}

		r.Out.Header.Set(headerName, headerValue)
	}

	return nil
}
