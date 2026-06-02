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

	gatewayconfig "gateway/internal/config"
	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/httpproxy/parser"
	"gateway/internal/metrics"
	"gateway/internal/token"
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
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperMetrics, metrics.ResourceTypeWebApp, http.DefaultTransport),
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

	clientLocation := claims.Device.Location
	clientGeoLatLong := ""
	if clientLocation != (token.GeoIPLocation{}) {
		clientGeoLatLong = fmt.Sprintf("%v,%v", clientLocation.Lat, clientLocation.Lon)
	}

	variables := map[string]string{
		gatewayconfig.JWT:              conn.GetToken(),
		gatewayconfig.Username:         claims.User.Username,
		gatewayconfig.Groups:           strings.Join(claims.User.Groups, ","),
		gatewayconfig.ClientGeoLatLong: clientGeoLatLong,
		gatewayconfig.ClientCity:       clientLocation.City,
		gatewayconfig.ClientRegion:     clientLocation.Region,
		gatewayconfig.ClientCountry:    clientLocation.Country,
	}

	for headerName, tmpl := range headers {
		headerValue, err := tmpl.Evaluate(variables)
		if err != nil {
			return fmt.Errorf("header %q: %w", headerName, err)
		}

		r.Out.Header.Set(headerName, headerValue)
	}

	return nil
}
