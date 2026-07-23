// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var errInvalidTokenType = errors.New("token type is invalid")

var allowedSigningMethods = []string{jwt.SigningMethodES256.Alg()}

type ClaimsWithHeaderType interface {
	getHeaderType() string
}

type ParserConfig struct {
	// Issuer is the expected JWT issuer (iss claim).
	Issuer string
	// Audience is the expected JWT audience (aud claim).
	Audience string
	// JWKSURL is the endpoint to fetch signing keys from when Keyfunc is not provided.
	JWKSURL string
	// Keyfunc to verify token. Default to using remote JWKs
	Keyfunc jwt.Keyfunc
}

type Parser struct {
	parser *jwt.Parser
	config ParserConfig
}

func NewParser(config ParserConfig) (*Parser, error) {
	if config.Keyfunc == nil {
		jwks, err := keyfunc.NewDefault([]string{config.JWKSURL})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS store: %w", err)
		}

		config.Keyfunc = jwks.Keyfunc
	}

	return &Parser{
		parser: jwt.NewParser(
			jwt.WithValidMethods(allowedSigningMethods),
			jwt.WithIssuer(config.Issuer),
			jwt.WithAudience(config.Audience),
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
