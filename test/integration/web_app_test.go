// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	gatewayconfig "gateway/internal/config"
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
			CertificateFile: "../data/proxy/tls.crt",
			PrivateKeyFile:  "../data/proxy/tls.key",
		},
		WebApp: &gatewayconfig.WebAppConfig{
			Headers: map[string]string{
				"Authorization":                 "Bearer {{jwt}}",
				"X-Twingate-Username":           "Overridden by GAT Token",
				"X-Twingate-Groups":             "{{groups}}",
				"X-Twingate-Client-Geo-LatLong": "{{clientGeoLatLong}}",
				"X-Twingate-Client-Geo-City":    "{{clientGeoCity}}",
				"X-Twingate-Client-Geo-Region":  "{{clientGeoRegion}}",
				"X-Twingate-Client-Geo-Country": "{{clientGeoCountry}}",
			},
		},
	}

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Named("test")

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
			"X-GAT-Token-Header":  "value preserved",
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
		"X-GAT-Token-Header":  "value preserved",
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
