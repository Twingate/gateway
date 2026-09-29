// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package webapp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"gateway/internal/backend/httpproxy"
	"gateway/internal/backend/webapp/template"
	"gateway/internal/frontend"
	"gateway/internal/metrics"
	"gateway/internal/token"
)

var (
	errNoPeerCertificate  = errors.New("upstream presented no certificate")
	errUnsupportedTLSMode = errors.New("unsupported upstream TLS mode")
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
		Transport: metrics.InstrumentRoundTripper(cfg.roundTripperMetrics, metrics.ResourceTypeWebApp, createUpstreamRoundTripper(cfg.caPool)),
	}

	return &Handler{proxy: proxy}
}

// createUpstreamRoundTripper sends each request through a transport dedicated to the upstream TLS
// mode in the connection's GAT, so pooled upstream connections are never reused across modes.
func createUpstreamRoundTripper(caPool *x509.CertPool) promhttp.RoundTripperFunc {
	transports := make(map[token.TLSClientMode]*http.Transport, len(token.TLSClientModes))
	for _, mode := range token.TLSClientModes {
		transports[mode] = createTransport(newUpstreamTLSConfig(mode, caPool))
	}

	return func(r *http.Request) (*http.Response, error) {
		mode := httpproxy.ProxyConnFromContext(r.Context()).GATClaims().Resource.GatewayMetadata.Upstream.TLSMode

		transport, ok := transports[mode]
		if !ok {
			return nil, fmt.Errorf("%w %q", errUnsupportedTLSMode, mode)
		}

		return transport.RoundTrip(r)
	}
}

// createTransport clones http.DefaultTransport to preserve its proxy, timeout,
// and HTTP/2 defaults and applies the given upstream TLS config.
func createTransport(tlsConfig *tls.Config) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return transport
}

// newUpstreamTLSConfig returns the TLS client config for connecting to an upstream in the given
// mode, verifying certificate chains against rootCAs. It returns nil for TLSClientModeNone.
func newUpstreamTLSConfig(mode token.TLSClientMode, rootCAs *x509.CertPool) *tls.Config {
	switch mode {
	case token.TLSClientModeNone:
		return nil
	case token.TLSClientModeInsecure:
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402 -- The resource explicitly opts out of upstream certificate verification
		}
	case token.TLSClientModeVerifyCA:
		// Disable the built-in verification, which always checks the hostname, and verify only the
		// certificate chain in VerifyConnection.
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402 -- The certificate chain is verified in VerifyConnection
			VerifyConnection:   verifyCertificateChain(rootCAs),
		}
	case token.TLSClientModeVerifyFull:
		fallthrough
	default:
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    rootCAs,
		}
	}
}

// verifyCertificateChain returns a VerifyConnection callback that verifies the peer's certificate
// chain against rootCAs without checking the hostname.
func verifyCertificateChain(rootCAs *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errNoPeerCertificate
		}

		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}

		if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: rootCAs, Intermediates: intermediates}); err != nil {
			return fmt.Errorf("verify upstream certificate: %w", err)
		}

		return nil
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

func buildVariables(conn *frontend.ProxyConn) map[string]string {
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

// downstreamScheme reports the scheme the protocol client used to reach the Gateway.
func downstreamScheme(conn *frontend.ProxyConn) string {
	if conn.GATClaims().ShouldUpgradeTLS() {
		return "https"
	}

	return "http"
}

func rewrite(r *httputil.ProxyRequest, conn *frontend.ProxyConn, headers map[string]*template.Template) error {
	scheme := "https"
	if conn.GATClaims().Resource.GatewayMetadata.Upstream.TLSMode == token.TLSClientModeNone {
		scheme = "http"
	}

	targetURL := &url.URL{
		Scheme: scheme,
		Host:   conn.GetUpstreamAddress(),
	}
	r.SetURL(targetURL)
	r.Out.Host = r.In.Host // preserve the client's Host

	for _, headerName := range clientIdentityHeaders {
		r.Out.Header.Del(headerName)
	}

	r.Out.Header.Set("X-Forwarded-Proto", downstreamScheme(conn))

	variables := buildVariables(conn)

	for headerName, tmpl := range headers {
		headerValue, err := tmpl.Evaluate(variables)
		if err != nil {
			return fmt.Errorf("header %q: %w", headerName, err)
		}

		setHeader(r, headerName, headerValue)
	}

	// Per-resource request header rewrites from the GAT are applied last, so they override
	// any config headers with the same name. A rewrite whose template fails to parse or
	// evaluate is skipped rather than failing the request.
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

		setHeader(r, headerName, headerValue)
	}

	return nil
}

func setHeader(r *httputil.ProxyRequest, name, value string) {
	switch http.CanonicalHeaderKey(name) {
	case "Host":
		r.Out.Host = value
	default:
		r.Out.Header.Set(name, value)
	}
}
