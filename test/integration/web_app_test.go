// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/logging"
	"gateway/internal/proxy"
	"gateway/internal/token"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

func TestWebApp(t *testing.T) {
	const gatewayPort = 8450

	echoServer := testutil.SetupHTTPEchoServer(t)
	upstreamAddress := echoServer.Listener.Addr().String()

	controller := fake.NewController(network, 8080)
	defer controller.Close()

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			Certificates: &gatewayconfig.TLSCertificateSources{
				Files: []gatewayconfig.TLSCertificateFileKeyPair{
					{
						CertificateFile: "../data/proxy/tls.crt",
						PrivateKeyFile:  "../data/proxy/tls.key",
					},
				},
			},
		},
		WebApp: &gatewayconfig.WebAppConfig{
			RequestHeaders: map[string]string{
				"Authorization":                 "Bearer {{jwt}}",
				"X-Twingate-Groups":             "{{groups}}",
				"X-Twingate-Client-Geo-LatLong": "{{clientGeoLatLong}}",
				"X-Twingate-Client-Geo-City":    "{{clientGeoCity}}",
				"X-Twingate-Client-Geo-Region":  "{{clientGeoRegion}}",
				"X-Twingate-Client-Geo-Country": "{{clientGeoCountry}}",
			},
		},
	}

	logger, logs := testutil.NewObservedLogger()

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	user := testutil.NewWebAppUser(
		&token.User{
			ID:       "user-webapp-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		token.GeoIPLocation{
			Lat:     37.5,
			Lon:     -122.4,
			Country: "US",
			Region:  "CA",
			City:    "San Mateo",
		},
		gatewayPort,
		upstreamAddress,
		controller.URL,
		map[string]string{
			"X-Twingate-Username": "{{username}}",
		},
	)
	defer user.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(user.URL)
	require.NoError(t, err, "failed to make HTTP request")

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read response body")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var echoResp testutil.EchoResponse

	err = json.Unmarshal(body, &echoResp)
	require.NoError(t, err, "failed to parse echo response")

	expectedHeaders := map[string]string{
		// From Gateway config
		"X-Twingate-Groups":             "OnCall,Engineering",
		"X-Twingate-Client-Geo-LatLong": "37.5,-122.4",
		"X-Twingate-Client-Geo-City":    "San Mateo",
		"X-Twingate-Client-Geo-Region":  "CA",
		"X-Twingate-Client-Geo-Country": "US",
		// From GAT Token
		"X-Twingate-Username": "alex@acme.com",
		// Downstream scheme
		"X-Forwarded-Proto": "http",
	}

	for header, expected := range expectedHeaders {
		assert.Equal(t, expected, echoResp.Headers.Get(header), "header %s mismatch", header)
	}

	var claims token.GATClaims

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	_, _, err = parser.ParseUnverified(strings.TrimPrefix(echoResp.Headers.Get("Authorization"), "Bearer "), &claims)
	require.NoError(t, err, "failed to parse JWT claims")

	assert.Equal(t, user.ID, claims.User.ID)
	assert.Equal(t, user.Username, claims.User.Username)
	assert.Equal(t, user.Groups, claims.User.Groups)

	expectedUser := map[string]any{
		"id":       "user-webapp-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForREST(t, logs, "/", expectedUser, http.StatusOK)
}

// TestWebAppTLSCertificates tests that a Web App with downstream TLS is served a webApp.tls
// certificate covering its SNI, and the tls certificate for any other name.
func TestWebAppTLSCertificates(t *testing.T) {
	const gatewayPort = 8451

	echoServer := testutil.SetupHTTPEchoServer(t)
	upstreamAddress := echoServer.Listener.Addr().String()

	controller := fake.NewController(network, 8080)
	defer controller.Close()

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			Certificates: &gatewayconfig.TLSCertificateSources{
				Files: []gatewayconfig.TLSCertificateFileKeyPair{
					{
						CertificateFile: "../data/proxy/tls.crt",
						PrivateKeyFile:  "../data/proxy/tls.key",
					},
				},
			},
		},
		WebApp: &gatewayconfig.WebAppConfig{
			TLS: &gatewayconfig.WebAppTLSConfig{
				Certificates: gatewayconfig.TLSCertificateSources{
					Files: []gatewayconfig.TLSCertificateFileKeyPair{
						{
							CertificateFile: "../data/api_server/tls.crt",
							PrivateKeyFile:  "../data/api_server/tls.key",
						},
					},
				},
			},
		},
	}

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logging.NewNop())
	require.NoError(t, err, "failed to create proxy")

	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	client := fake.NewClient(
		&token.User{ID: "user-webapp-1", Username: "alex@acme.com", Groups: []string{"OnCall", "Engineering"}},
		token.GeoIPLocation{Lat: 37.5, Lon: -122.4, Country: "US", Region: "CA", City: "San Mateo"},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controller.URL,
		upstreamAddress,
		token.ResourceTypeWebApp,
		fake.WithDownstreamTLS(),
	)
	t.Cleanup(client.Close)

	webAppCert, err := tls.LoadX509KeyPair("../data/api_server/tls.crt", "../data/api_server/tls.key")
	require.NoError(t, err)

	proxyCert, err := tls.LoadX509KeyPair("../data/proxy/tls.crt", "../data/proxy/tls.key")
	require.NoError(t, err)

	dial := func(serverName string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", client.Address, &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402 -- the test asserts which certificate is served, not that it is trusted
		})
	}

	// The proxy certificate covers localhost too. The Web App certificates load asynchronously,
	// so wait until the handshake is served the Web App certificate.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		conn, err := dial("localhost")
		require.NoError(c, err)

		defer conn.Close()

		assert.Equal(c, webAppCert.Certificate[0], conn.ConnectionState().PeerCertificates[0].Raw)
	}, 5*time.Second, 50*time.Millisecond)

	conn, err := dial("kubernetes")
	require.NoError(t, err)

	defer conn.Close()

	assert.Equal(t, proxyCert.Certificate[0], conn.ConnectionState().PeerCertificates[0].Raw)
}
