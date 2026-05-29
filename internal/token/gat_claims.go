// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap/zapcore"
)

const supportedVersion = "1"

var (
	errInvalidPublicKey   = errors.New("not a valid public key")
	errUnsupportedVersion = errors.New("unsupported version")
)

type GATClaims struct {
	jwt.RegisteredClaims

	Version         string           `json:"ver"`
	RenewAt         *jwt.NumericDate `json:"rnw"`
	ClientPublicKey PublicKey        `json:"cpk"`
	User            User             `json:"user"`
	Device          Device           `json:"device"`
	Resource        Resource         `json:"resource"`
}

func (p GATClaims) Validate() error {
	validations := []struct {
		condition bool
		fieldName string
	}{
		{p.Version == "", "ver"},
		{p.RenewAt == nil, "rnw"},
		{p.ClientPublicKey == (PublicKey{}), "cpk"},
		{p.User.ID == "", "user.id"},
		{p.User.Username == "", "user.username"},
		{p.Resource.ID == "", "resource.id"},
		{p.Resource.Address == "", "resource.address"},
	}

	for _, v := range validations {
		if v.condition {
			return fmt.Errorf("%w \"%s\"", jwt.ErrTokenRequiredClaimMissing, v.fieldName)
		}
	}

	if p.Version != supportedVersion {
		return fmt.Errorf("%w: %w %q", jwt.ErrTokenInvalidClaims, errUnsupportedVersion, p.Version)
	}

	return nil
}

func (p GATClaims) getHeaderType() string {
	return "GAT"
}

type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

func (u User) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", u.ID)
	enc.AddString("username", u.Username)
	err := enc.AddArray("groups", zapcore.ArrayMarshalerFunc(func(arrayEnc zapcore.ArrayEncoder) error {
		for _, group := range u.Groups {
			arrayEnc.AppendString(group)
		}

		return nil
	}))

	return err
}

type GeoIPLocation struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Country string  `json:"country,omitempty"`
	Region  string  `json:"region,omitempty"`
	City    string  `json:"city,omitempty"`
}

type Device struct {
	ID       string        `json:"id"`
	Location GeoIPLocation `json:"location,omitzero"`
}

type ResourceType = string

const (
	ResourceTypeKubernetes = "KUBERNETES"
	ResourceTypeSSH        = "SSH"
	ResourceTypeWebApp     = "WEB_APP"
)

type Resource struct {
	ID      string       `json:"id"`
	Type    ResourceType `json:"type"`
	Address string       `json:"address"`
}

// PublicKey is a wrapper for ecdsa.PublicKey that adds support for JSON
// marshaling and unmarshaling. It uses PEM encoding followed by base64 encoding
// to safely transport the public key in JSON format.
type PublicKey struct {
	ecdsa.PublicKey
}

// MarshalJSON implements the json.Marshaler interface.
// It converts the ECDSA public key to PKIX form, PEM encodes it,
// and then base64 encodes the result for safe JSON transport.
func (key PublicKey) MarshalJSON() ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	base64Encoded := base64.StdEncoding.EncodeToString(pemBytes)

	return json.Marshal(base64Encoded)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It processes the JSON string containing base64-encoded PEM data,
// decodes it, and reconstructs the original ECDSA public key.
func (key *PublicKey) UnmarshalJSON(data []byte) error {
	var base64String string
	if err := json.Unmarshal(data, &base64String); err != nil {
		return fmt.Errorf("%w: invalid JSON value %w", errInvalidPublicKey, err)
	}

	pemBytes, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return fmt.Errorf("%w: failed to decode Base64 %w", errInvalidPublicKey, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("%w: failed to decode PEM block", errInvalidPublicKey)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse public key", errInvalidPublicKey)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: not an ECDSA public key", errInvalidPublicKey)
	}

	key.PublicKey = *publicKey

	return nil
}
