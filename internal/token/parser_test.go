// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenService struct {
	signingKey *ecdsa.PrivateKey
	keyfunc    jwt.Keyfunc
}

func (ts *tokenService) signToken(claims jwt.MapClaims, headers map[string]any) (string, error) {
	c := jwt.MapClaims{
		"iss": "twingate",
		"aud": "acme",
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	for k, v := range claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	if headers != nil {
		token.Header = headers
	}

	signed, err := token.SignedString(ts.signingKey)
	if err != nil {
		return "", err
	}

	return signed, nil
}

func newTokenService() *tokenService {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return &tokenService{
		signingKey: privateKey,
		keyfunc:    func(_token *jwt.Token) (any, error) { return &privateKey.PublicKey, nil },
	}
}

type CustomClaims struct {
	jwt.RegisteredClaims
}

func (c *CustomClaims) getHeaderType() string {
	return "custom"
}

func TestParser_ParseWithClaims(t *testing.T) {
	tokenService := newTokenService()
	parser, _ := NewParser(ParserConfig{
		Network: "acme",
		Host:    "twingate.com",
		Keyfunc: tokenService.keyfunc,
	})

	t.Run("Valid token type", func(t *testing.T) {
		claims := &CustomClaims{}
		headers := map[string]any{"typ": "custom", "alg": "ES256"}
		tokenStr, err := tokenService.signToken(jwt.MapClaims{}, headers)
		require.NoError(t, err)

		token, err := parser.ParseWithClaims(tokenStr, claims)

		require.NoError(t, err)
		require.NotNil(t, token)
		require.True(t, token.Valid)
	})

	tests := []struct {
		name          string
		headers       map[string]any
		expectedError error
	}{
		{
			name:          "Missing token type",
			headers:       map[string]any{},
			expectedError: errInvalidTokenType,
		},
		{
			name:          "Invalid token type",
			headers:       map[string]any{"typ": "invalid"},
			expectedError: errInvalidTokenType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &CustomClaims{}
			headers := map[string]any{"alg": "ES256"}
			maps.Copy(headers, tt.headers)
			tokenStr, err := tokenService.signToken(jwt.MapClaims{}, headers)
			require.NoError(t, err)

			token, err := parser.ParseWithClaims(tokenStr, claims)

			require.ErrorIs(t, err, tt.expectedError)
			require.Nil(t, token)
		})
	}
}

func TestNewParser(t *testing.T) {
	tokenService := newTokenService()

	parser, err := NewParser(ParserConfig{
		Network: "acme",
		Host:    "twingate.com",
		Keyfunc: tokenService.keyfunc,
	})
	require.NoError(t, err)
	require.NotNil(t, parser)

	t.Run("Valid token", func(t *testing.T) {
		tokenStr, err := tokenService.signToken(jwt.MapClaims{}, nil)
		require.NoError(t, err)

		token, err := parser.ParseWithClaims(tokenStr, jwt.MapClaims{})

		require.NoError(t, err)
		require.NotNil(t, token)
		require.True(t, token.Valid)
	})

	tests := []struct {
		name          string
		claims        jwt.MapClaims
		headers       map[string]any
		expectedError error
	}{
		{
			name:          "Invalid signing method",
			headers:       map[string]any{"alg": "HS256"}, // Signing with a symmetric key
			expectedError: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "Invalid audience",
			claims: jwt.MapClaims{
				"aud": "oscorp",
			},
			expectedError: jwt.ErrTokenInvalidAudience,
		},
		{
			name: "Invalid issuer",
			claims: jwt.MapClaims{
				"iss": "twingate-test",
			},
			expectedError: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "Issued at timestamp should not be in the future",
			claims: jwt.MapClaims{
				"iat": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			expectedError: jwt.ErrTokenInvalidClaims,
		},
		{
			name: "Expiration claim must exists",
			claims: jwt.MapClaims{
				"exp": nil,
			},
			expectedError: jwt.ErrTokenInvalidClaims,
		},
		{
			name: "Expiration timestamp should not be in the past",
			claims: jwt.MapClaims{
				"exp": jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			},
			expectedError: jwt.ErrTokenExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr, err := tokenService.signToken(tt.claims, tt.headers)
			require.NoError(t, err)

			token, err := parser.ParseWithClaims(tokenStr, jwt.MapClaims{})

			require.ErrorIs(t, err, tt.expectedError)
			require.Nil(t, token)
		})
	}
}

func TestGetIssuer(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		issuer string
	}{
		{name: "exact match", host: "twingate.com", issuer: "twingate"},
		{name: "sharded host", host: "us1.twingate.com", issuer: "twingate"},
		{name: "unknown host", host: "unknown-dev.opstg.com", issuer: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.issuer, getIssuer(tt.host))
		})
	}
}
