// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var errInvalidTokenType = errors.New("token type is invalid")

var allowedSigningMethods = []string{jwt.SigningMethodES256.Alg()}

var allowedIssuerByHost = map[string]string{
	"test":          "twingate-local",
	"dev.opstg.com": "twingate-dev",
	"stg.opstg.com": "twingate-stg",
	"twingate.com":  "twingate",
}

func issuerForHost(host string) string {
	for domain, issuer := range allowedIssuerByHost {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return issuer
		}
	}

	return ""
}

type ClaimsWithHeaderType interface {
	getHeaderType() string
}

type ParserConfig struct {
	// Twingate network ID
	Network string
	// Twingate service domain
	Host string
	// Keyfunc to verify token. Default to using remote JWKs
	Keyfunc jwt.Keyfunc
}

type Parser struct {
	parser *jwt.Parser
	config ParserConfig
}

func NewParser(config ParserConfig) (*Parser, error) {
	if config.Keyfunc == nil {
		jwkURL := fmt.Sprintf("https://%s.%s/api/v1/jwk/ec", config.Network, config.Host)

		jwks, err := keyfunc.NewDefault([]string{jwkURL})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS store: %w", err)
		}

		config.Keyfunc = jwks.Keyfunc
	}

	return &Parser{
		parser: jwt.NewParser(
			jwt.WithValidMethods(allowedSigningMethods),
			jwt.WithIssuer(issuerForHost(config.Host)),
			jwt.WithAudience(config.Network),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
		),
		config: config,
	}, nil
}

func (p *Parser) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := p.parser.ParseWithClaims(tokenString, claims, p.config.Keyfunc)
	if err != nil {
		return nil, err
	}

	if claim, ok := claims.(ClaimsWithHeaderType); ok {
		if headerTyp, ok := token.Header["typ"].(string); !ok || headerTyp != claim.getHeaderType() {
			return nil, errInvalidTokenType
		}
	}

	return token, nil
}
