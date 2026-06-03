// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

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

	echoServer := testutil.SetupWebAppEchoServer(t)
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
				"Authorization":                 "Bearer {{twingate.jwt}}",
				"X-Twingate-Username":           "{{twingate.username}}",
				"X-Twingate-Groups":             "{{twingate.groups}}",
				"X-Twingate-Client-Geo-LatLong": "{{twingate.clientGeoLatLong}}",
				"X-Twingate-Client-Geo-City":    "{{twingate.clientGeoCity}}",
				"X-Twingate-Client-Geo-Region":  "{{twingate.clientGeoRegion}}",
				"X-Twingate-Client-Geo-Country": "{{twingate.clientGeoCountry}}",
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
	)
	defer user.Close()

	resp, err := http.Get(user.URL)
	require.NoError(t, err, "failed to make HTTP request")

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read response body")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var echoResp testutil.EchoResponse

	err = json.Unmarshal(body, &echoResp)
	require.NoError(t, err, "failed to parse echo response")

	assert.Equal(t, "/", echoResp.Path)

	expectedHeaders := map[string]string{
		"X-Twingate-Username":           "alex@acme.com",
		"X-Twingate-Groups":             "OnCall,Engineering",
		"X-Twingate-Client-Geo-LatLong": "37.5,-122.4",
		"X-Twingate-Client-Geo-City":    "San Mateo",
		"X-Twingate-Client-Geo-Region":  "CA",
		"X-Twingate-Client-Geo-Country": "US",
	}

	for header, expected := range expectedHeaders {
		assert.Equal(t, expected, echoResp.Headers.Get(header), "header %s mismatch", header)
	}

	authHeader := echoResp.Headers.Get("Authorization")
	assert.True(t, strings.HasPrefix(authHeader, "Bearer "), "Authorization header should start with 'Bearer '")
	assert.Greater(t, len(authHeader), len("Bearer "), "Authorization header should contain a JWT after 'Bearer '")

	expectedUser := map[string]any{
		"id":       "user-webapp-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}
	testutil.AssertLogsForREST(t, logs, "/", expectedUser, http.StatusOK)
}
