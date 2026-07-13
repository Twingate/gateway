// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gateway/internal/token"
)

type client struct {
	privateKey *ecdsa.PrivateKey
}

func (c client) getPublicKey() token.PublicKey {
	return token.PublicKey{PublicKey: c.privateKey.PublicKey}
}

func (c client) sign(t string) string {
	hash := sha256.Sum256([]byte(t))
	signature, _ := ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])

	return base64.StdEncoding.EncodeToString(signature)
}

func newClient() client {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return client{privateKey}
}

func newGATTokenClaims(clientPublicKey token.PublicKey) token.GATClaims {
	return token.GATClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "twingate",
			Audience:  jwt.ClaimStrings{"acme"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Version:         "1",
		RenewAt:         jwt.NewNumericDate(time.Now().Add(time.Minute)),
		ClientPublicKey: clientPublicKey,
		User: token.User{
			ID:       "user-1",
			Username: "user@acme.com",
			Groups:   []string{"Everyone", "Engineering"},
		},
		Device: token.Device{
			ID: "device-1",
		},
		Resource: token.Resource{
			ID:      "resource-1",
			Address: "example.com",
			GatewayMetadata: token.GatewayMetadata{
				Downstream: token.Downstream{Port: 443},
				Upstream:   token.Upstream{Port: 443},
			},
		},
	}
}

func createParserAndGATToken(t *testing.T, claims token.GATClaims) (*token.Parser, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parser, err := token.NewParser(token.ParserConfig{
		Issuer:   "twingate",
		Audience: "acme",
		Keyfunc: func(_token *jwt.Token) (any, error) {
			return &privateKey.PublicKey, nil
		},
	})
	require.NoError(t, err)

	gatToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	gatToken.Header["typ"] = "GAT"
	tokenStr, err := gatToken.SignedString(privateKey)
	require.NoError(t, err)

	return parser, tokenStr
}

func TestConnectValidator_ParseConnect(t *testing.T) {
	c := newClient()
	gatClaims := newGATTokenClaims(c.getPublicKey())
	parser, signedToken := createParserAndGATToken(t, gatClaims)

	sigData := "test-signature"

	t.Run("Successful authentication", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		signature := c.sign(sigData)
		// create request
		req := httptest.NewRequest(http.MethodConnect, "Example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, signature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		require.NoError(t, err)
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
		assert.Equal(t, signedToken, connectInfo.Token)
	})

	t.Run("Non-CONNECT method", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with GET method instead of CONNECT
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusMethodNotAllowed, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "expected CONNECT request")
		assert.Nil(t, connectInfo.Claims)
		assert.Empty(t, connectInfo.ConnID)
		assert.Empty(t, connectInfo.Token)
	})

	t.Run("Missing auth header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without auth header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusProxyAuthRequired, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "missing identity header")
		assert.Nil(t, connectInfo.Claims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid token", func(t *testing.T) {
		parser, invalidToken := createParserAndGATToken(
			t,
			token.GATClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				ClientPublicKey: c.getPublicKey(),
			},
		)
		validator := &MessageValidator{TokenParser: parser}

		// create request with invalid token
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+invalidToken)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.Error(t, httpErr.Err)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to parse token")
		assert.Nil(t, connectInfo.Claims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid signature format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with invalid signature in header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, "invalid-signature")
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.Error(t, httpErr.Err)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to decode client signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Missing signature header", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request without signature header
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.NoError(t, httpErr.Err)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid ASN.1 format", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with signature with valid base64 but invalid ASN.1
		invalidSignature := base64.StdEncoding.EncodeToString([]byte("not valid ASN.1 format"))
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)
		req.Header.Set(AuthSignatureHeaderKey, invalidSignature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.NoError(t, httpErr.Err)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Signature verification failure", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request with mismatched signature
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign("different-token")
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.NoError(t, httpErr.Err)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify signature")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid destination (not in token)", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "website.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.NoError(t, httpErr.Err)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to verify CONNECT destination")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Invalid destination, missing", func(t *testing.T) {
		validator := &MessageValidator{TokenParser: parser}

		// create request
		req := httptest.NewRequest(http.MethodConnect, "", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+signedToken)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)

		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		var httpErr *HTTPError

		require.ErrorAs(t, err, &httpErr)
		require.Error(t, httpErr.Err)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Error(), "failed to parse CONNECT destination")
		assert.Equal(t, *connectInfo.Claims, gatClaims)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})

	t.Run("Rewrites destination port to upstream port", func(t *testing.T) {
		claims := newGATTokenClaims(c.getPublicKey())
		claims.Resource.GatewayMetadata.Upstream = token.Upstream{Port: 8443}
		parserRewrite, tokenRewrite := createParserAndGATToken(t, claims)
		validator := &MessageValidator{TokenParser: parserRewrite}

		// client targets the downstream port 443; backend must be dialed on upstream 8443
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set(AuthHeaderKey, "Bearer "+tokenRewrite)

		signature := c.sign(sigData)
		req.Header.Set(AuthSignatureHeaderKey, signature)
		req.Header.Set(ConnIDHeaderKey, "conn-id")

		connectInfo, err := validator.ParseConnect(req, []byte(sigData))

		require.NoError(t, err)
		assert.Equal(t, "example.com:8443", connectInfo.Address)
		assert.Equal(t, "conn-id", connectInfo.ConnID)
	})
}

func TestHTTPError_Error(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
		want    string
	}{
		{
			name:    "Not Found",
			code:    404,
			message: "Not Found",
			want:    "404: Not Found",
		},
		{
			name:    "Internal Server Error",
			code:    500,
			message: "Internal Server Error",
			want:    "500: Internal Server Error",
		},
		{
			name:    "Bad Request",
			code:    400,
			message: "Bad Request",
			want:    "400: Bad Request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &HTTPError{
				Code:    tt.code,
				Message: tt.message,
			}
			assert.Equal(t, tt.want, e.Error())
		})
	}
}

func TestResolveUpstreamAddress(t *testing.T) {
	metadata := token.GatewayMetadata{
		Downstream: token.Downstream{Port: 443},
		Upstream:   token.Upstream{Port: 8443},
	}

	tests := []struct {
		name        string
		host        string
		port        string
		metadata    token.GatewayMetadata
		wantAddress string
		wantCode    int
		wantMessage string
	}{
		{
			name:        "maps downstream port to upstream port",
			host:        "example.com",
			port:        "443",
			metadata:    metadata,
			wantAddress: "example.com:8443",
		},
		{
			name:        "non-numeric port",
			host:        "example.com",
			port:        "abc",
			metadata:    metadata,
			wantCode:    http.StatusBadRequest,
			wantMessage: "failed to parse CONNECT destination port",
		},
		{
			name:        "port mismatch with downstream port",
			host:        "example.com",
			port:        "8443",
			metadata:    metadata,
			wantCode:    http.StatusBadRequest,
			wantMessage: "CONNECT destination port 8443 does not match token downstream port 443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, httpErr := resolveUpstreamAddress(tt.host, tt.port, tt.metadata)

			if tt.wantCode != 0 {
				require.NotNil(t, httpErr)
				assert.Equal(t, tt.wantCode, httpErr.Code)
				assert.Contains(t, httpErr.Message, tt.wantMessage)
				assert.Empty(t, got)

				return
			}

			require.Nil(t, httpErr)
			assert.Equal(t, tt.wantAddress, got)
		})
	}
}

func TestMatchResourceAddress(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{
			name:    "exact match",
			pattern: "api.example.com",
			host:    "api.example.com",
			want:    true,
		},
		{
			name:    "exact match case insensitive",
			pattern: "api.example.com",
			host:    "Api.example.coM",
			want:    true,
		},
		{
			name:    "exact match mismatch",
			pattern: "api.example.com",
			host:    "other.example.com",
			want:    false,
		},
		{
			name:    "wildcard matches single label",
			pattern: "*.example.com",
			host:    "api.example.com",
			want:    true,
		},
		{
			name:    "wildcard reject non-matching suffix",
			pattern: "*.example.com",
			host:    "api.invalid.com",
			want:    false,
		},
		{
			name:    "wildcard reject invalid starting label",
			pattern: "*.example.com",
			host:    "-invalid.example.com",
			want:    false,
		},
		{
			name:    "wildcard reject invalid ending label",
			pattern: "*.example.com",
			host:    "invalid-.example.com",
			want:    false,
		},
		{
			name:    "wildcard with top-level domain",
			pattern: "*.com",
			host:    "twingate.com",
			want:    true,
		},
		{
			name:    "wildcard match case insensitive",
			pattern: "*.Example.COM",
			host:    "API.example.com",
			want:    true,
		},
		{
			name:    "wildcard does not match bare domain",
			pattern: "*.example.com",
			host:    "example.com",
			want:    false,
		},
		{
			name:    "wildcard does not match multi-level subdomain",
			pattern: "*.example.com",
			host:    "foo.bar.example.com",
			want:    false,
		},
		{
			name:    "non-leftmost wildcard rejected",
			pattern: "api.*.com",
			host:    "api.example.com",
			want:    false,
		},
		{
			name:    "bare wildcard rejected",
			pattern: "*",
			host:    "example.com",
			want:    false,
		},
		{
			name:    "wildcard without dot rejected",
			pattern: "*example.com",
			host:    "apiexample.com",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchResourceAddress(tt.pattern, tt.host))
		})
	}
}
