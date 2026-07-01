// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGATClaims_ShouldUpgradeTLS(t *testing.T) {
	tests := []struct {
		name         string
		resourceType ResourceType
		expected     bool
	}{
		{
			name:         "Kubernetes should upgrade TLS",
			resourceType: ResourceTypeKubernetes,
			expected:     true,
		},
		{
			name:         "SSH should not upgrade TLS",
			resourceType: ResourceTypeSSH,
			expected:     false,
		},
		{
			name:         "Web app should not upgrade TLS",
			resourceType: ResourceTypeWebApp,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &GATClaims{
				Resource: Resource{Type: tt.resourceType},
			}
			assert.Equal(t, tt.expected, claims.ShouldUpgradeTLS())
		})
	}
}

func TestGATTokenClaims_Validate(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var validClaims = GATClaims{
		Version:         "1",
		RenewAt:         jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		ClientPublicKey: PublicKey{privateKey.PublicKey},
		User: User{
			ID:       "user-1",
			Username: "username",
		},
		Device: Device{
			ID: "device-1",
			Location: GeoIPLocation{
				Lat:     37.7749,
				Lon:     -122.4194,
				Country: "US",
				Region:  "California",
				City:    "San Francisco",
			},
		},
		Resource: Resource{
			ID:      "resource-1",
			Type:    "KUBERNETES",
			Address: "resource.internal",
			GatewayMetadata: GatewayMetadata{
				Downstream: Downstream{Port: 443},
			},
		},
	}

	t.Run("Valid claims", func(t *testing.T) {
		err := validClaims.Validate()
		require.NoError(t, err)
	})

	tests := []struct {
		name                 string
		setupFn              func(*GATClaims)
		expectedError        error
		expectedErrorMessage string
	}{
		{
			name: "Missing version",
			setupFn: func(claims *GATClaims) {
				claims.Version = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"ver\"",
		},
		{
			name: "Missing renew at",
			setupFn: func(claims *GATClaims) {
				claims.RenewAt = nil
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"rnw\"",
		},
		{
			name: "Missing client public key",
			setupFn: func(claims *GATClaims) {
				claims.ClientPublicKey = PublicKey{}
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"cpk\"",
		},
		{
			name: "Missing user ID",
			setupFn: func(claims *GATClaims) {
				claims.User.ID = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"user.id\"",
		},
		{
			name: "Missing user username",
			setupFn: func(claims *GATClaims) {
				claims.User.Username = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"user.username\"",
		},
		{
			name: "Missing resource ID",
			setupFn: func(claims *GATClaims) {
				claims.Resource.ID = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"resource.id\"",
		},
		{
			name: "Missing resource address",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Address = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"resource.address\"",
		},
		{
			name: "Unsupported version",
			setupFn: func(claims *GATClaims) {
				claims.Version = "2"
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "unsupported version \"2\"",
		},
		{
			name: "Missing downstream port",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Downstream.Port = 0
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\"=0",
		},
		{
			name: "Negative downstream port",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Downstream.Port = -1
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\"=-1",
		},
		{
			name: "Downstream port out of range",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Downstream.Port = 65536
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\"=65536",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validClaims
			tt.setupFn(&claims)

			err := claims.Validate()

			require.ErrorIs(t, err, tt.expectedError)
			require.ErrorContains(t, err, tt.expectedErrorMessage)
		})
	}
}

func TestPublicKey_MarshalJSON(t *testing.T) {
	t.Run("Valid public key", func(t *testing.T) {
		x, _ := new(big.Int).SetString("ccf05474241308bffdca1392dbb28fd98deeaf8ca15f04b3cf163c6da3b10c94", 16)
		y, _ := new(big.Int).SetString("764efdffccbf662172d8256b7bf46c4d6bf1efd5a205fd12a162db4eb01a2216", 16)
		pubKey := &PublicKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		}

		jsonBytes, err := pubKey.MarshalJSON()

		require.NoError(t, err)
		require.JSONEq(t, "\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFelBCVWRDUVRDTC85eWhPUzI3S1AyWTN1cjR5aApYd1N6enhZOGJhT3hESlIyVHYzL3pMOW1JWExZSld0NzlHeE5hL0h2MWFJRi9SS2hZdHRPc0JvaUZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"", string(jsonBytes))
	})

	t.Run("Invalid public key", func(t *testing.T) {
		pubKey := &PublicKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(1),
				Y:     big.NewInt(1),
			},
		}

		_, err := pubKey.MarshalJSON()

		require.ErrorContains(t, err, "P256 point not on curve")
	})
}

func TestPublicKey_UnmarshalJSON(t *testing.T) {
	t.Run("Valid public key", func(t *testing.T) {
		jsonBytes := []byte("\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFelBCVWRDUVRDTC85eWhPUzI3S1AyWTN1cjR5aApYd1N6enhZOGJhT3hESlIyVHYzL3pMOW1JWExZSld0NzlHeE5hL0h2MWFJRi9SS2hZdHRPc0JvaUZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"")

		var publicKey PublicKey

		err := publicKey.UnmarshalJSON(jsonBytes)
		require.NoError(t, err)

		require.Equal(t, publicKey.Curve, elliptic.P256())
		require.Equal(t, "ccf05474241308bffdca1392dbb28fd98deeaf8ca15f04b3cf163c6da3b10c94", fmt.Sprintf("%x", publicKey.X))
		require.Equal(t, "764efdffccbf662172d8256b7bf46c4d6bf1efd5a205fd12a162db4eb01a2216", fmt.Sprintf("%x", publicKey.Y))
	})

	tests := []struct {
		name                 string
		json                 []byte
		expectedError        error
		expectedErrorMessage string
	}{
		{
			name:                 "Invalid JSON value",
			json:                 []byte("3"),
			expectedError:        errInvalidPublicKey,
			expectedErrorMessage: "invalid JSON value",
		},
		{
			name:                 "Invalid Base64",
			json:                 []byte("\"invalid\""),
			expectedError:        errInvalidPublicKey,
			expectedErrorMessage: "failed to decode Base64",
		},
		{
			name:                 "Invalid PEM block",
			json:                 []byte("\"aW52YWxpZC1wZW0K\""),
			expectedError:        errInvalidPublicKey,
			expectedErrorMessage: "failed to decode PEM block",
		},
		{
			name:                 "Invalid public key",
			json:                 []byte("\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KYVc1MllXeHBaQzFyWlhrPQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0KCg==\""),
			expectedError:        errInvalidPublicKey,
			expectedErrorMessage: "failed to parse public key",
		},
		{
			name: "Invalid ECDSA public key",
			// This is a RSA public key
			json:                 []byte("\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUExaFQxNWdxdnhpeWFnTnBFNXJxNQowRm43akFhTnZmNG13S2FReTBtdThkcEV5bFNKNm5zeU9KVGgwSjZQY1RWQ2RLT21ySzB6YUloSTFmZi9jRWJHCkRZNFI1akh4TDg1R2RkTWp6VTZMUWxzaG85SS9UVWhRYkIrdmlUM3ZPQzVERDA3TnRGd25qMEl4RmovY1VwTWUKSGtoT1FZY0xIUVIvMkJ6OVZWZkRXUFpxMml0V2Z5dndYdGF5T205SUxWS1dSVDY3K0JQYTNyd0tLeDhxcjV6UwphUXNsV3dFeVByb0ZtZ3gzWU01ZWNVZjNhTTJBQ2JobjlaTXBRTTRJZ05TekpmVURGQTN0V1k5czJRRkkrWkRuCm1UZlhvVUtIR1NkYVZ1bEY0am5waFlQL1N2dGFlNFc2cVFSQkRrMEpsOGptT2o3S3ZPNEdtcnBRWVE2SnB2Q2MKSXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\""),
			expectedError:        errInvalidPublicKey,
			expectedErrorMessage: "not an ECDSA public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var publicKey PublicKey

			err := publicKey.UnmarshalJSON(tt.json)

			require.ErrorIs(t, err, tt.expectedError)
			require.ErrorContains(t, err, tt.expectedErrorMessage)
		})
	}
}
