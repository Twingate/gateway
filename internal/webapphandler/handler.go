// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapphandler

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"gateway/internal/connect"
	"gateway/internal/httpproxy"
	"gateway/internal/metrics"
	"gateway/internal/webapphandler/template"
)

type Handler struct {
	proxy http.Handler
}

func NewHandler(cfg Config) *Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			conn := httpproxy.ProxyConnFromContext(r.In.Context())

			if err := rewrite(r, conn, cfg.requestHeaders); err != nil {
				cfg.logger.Error("failed to rewrite headers", zap.Error(err))
				panic(err)
			}
		},
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperMetrics, metrics.ResourceTypeWebApp, createTransport(cfg.caPool)),
	}

	return &Handler{proxy: proxy}
}

// createTransport clones http.DefaultTransport to preserve its proxy, timeout,
// and HTTP/2 defaults and pins upstream TLS verification to the given CA pool.
func createTransport(caPool *x509.CertPool) *http.Transport {
	transport := &http.Transport{}
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	}

	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caPool,
	}

	return transport
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

func buildVariables(conn *connect.ProxyConn) map[string]string {
	claims := conn.GATClaims()
	clientLocation := claims.Device.Location

	latLong := ""
	if clientLocation.Lat != 0 || clientLocation.Lon != 0 {
		latLong = fmt.Sprintf("%v,%v", clientLocation.Lat, clientLocation.Lon)
	}

	return map[string]string{
		template.JWT:              conn.GetToken(),
		template.Username:         claims.User.Username,
		template.Groups:           strings.Join(claims.User.Groups, ","),
		template.ClientGeoLatLong: latLong,
		template.ClientGeoCity:    clientLocation.City,
		template.ClientGeoRegion:  clientLocation.Region,
		template.ClientGeoCountry: clientLocation.Country,
	}
}

// clientIdentityHeaders are stripped from the upstream request so a client cannot spoof its
// identity. The stdlib reverse proxy already strips the standard Forwarded/X-Forwarded-* set;
// these are the identity headers it leaves in place.
var clientIdentityHeaders = []string{"X-Real-IP", "X-Forwarded-Port", "X-Forwarded-Server"}

func rewrite(r *httputil.ProxyRequest, conn *connect.ProxyConn, headers map[string]*template.Template) error {
	scheme := "http"
	if conn.GATClaims().Resource.GatewayMetadata.Upstream.TLS {
		scheme = "https"
	}

	targetURL := &url.URL{
		Scheme: scheme,
		Host:   conn.GetAddress(),
	}
	r.SetURL(targetURL)
	r.Out.Host = r.In.Host // preserve the client's Host

	for _, headerName := range clientIdentityHeaders {
		r.Out.Header.Del(headerName)
	}

	variables := buildVariables(conn)

	for headerName, tmpl := range headers {
		headerValue, err := tmpl.Evaluate(variables)
		if err != nil {
			return fmt.Errorf("header %q: %w", headerName, err)
		}

		r.Out.Header.Set(headerName, headerValue)
	}

	// Per-resource request header rewrites from the GAT are applied last, so they override
	// any config headers with the same name. Malformed or unsupported headers are skipped
	// rather than failing the request.
	for headerName, value := range conn.GATClaims().Resource.GatewayMetadata.RequestHeaderRewrites {
		tmpl, err := template.New(value)
		if err != nil {
			conn.Logger.Warn("skipping GAT request header rewrite", zap.String("header", headerName), zap.Error(err))

			continue
		}

		headerValue, err := tmpl.Evaluate(variables)
		if err != nil {
			conn.Logger.Warn("skipping GAT request header rewrite", zap.String("header", headerName), zap.Error(err))

			continue
		}

		r.Out.Header.Set(headerName, headerValue)
	}

	return nil
}
