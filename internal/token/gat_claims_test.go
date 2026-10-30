// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
		name              string
		resourceType      ResourceType
		downstreamTLSMode TLSServerMode
		expected          bool
	}{
		{
			name:         "Kubernetes should upgrade TLS",
			resourceType: ResourceTypeKubernetes,
			expected:     true,
		},
		{
			name:              "SSH should not upgrade TLS",
			resourceType:      ResourceTypeSSH,
			downstreamTLSMode: TLSServerModeTLS13,
			expected:          false,
		},
		{
			name:              "Web app with downstream TLS mode none should not upgrade TLS",
			resourceType:      ResourceTypeWebApp,
			downstreamTLSMode: TLSServerModeNone,
			expected:          false,
		},
		{
			name:         "Web app without downstream TLS mode should not upgrade TLS",
			resourceType: ResourceTypeWebApp,
			expected:     false,
		},
		{
			name:              "Web app with downstream TLS mode TLS13 should upgrade TLS",
			resourceType:      ResourceTypeWebApp,
			downstreamTLSMode: TLSServerModeTLS13,
			expected:          true,
		},
		{
			name:              "PostgreSQL should not upgrade TLS",
			resourceType:      ResourceTypePostgreSQL,
			downstreamTLSMode: TLSServerModeTLS13,
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &GATClaims{
				Resource: Resource{
					Type: tt.resourceType,
					GatewayMetadata: GatewayMetadata{
						Downstream: Downstream{TLSMode: tt.downstreamTLSMode},
					},
				},
			}
			assert.Equal(t, tt.expected, claims.ShouldUpgradeTLS())
		})
	}
}

func TestGATTokenClaims_Validate(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var validClaims = GATClaims{
		Type:            "GAT",
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
			Aliases: []string{"app.internal"},
			GatewayMetadata: GatewayMetadata{
				Downstream: Downstream{Port: 443},
				Upstream:   Upstream{Port: 8443},
			},
		},
	}

	t.Run("Valid claims", func(t *testing.T) {
		err := validClaims.Validate()
		require.NoError(t, err)
	})

	validTLSModes := []struct {
		name       string
		downstream TLSServerMode
		upstream   TLSClientMode
	}{
		{name: "downstream TLS13", downstream: TLSServerModeTLS13, upstream: TLSClientModeVerifyFull},
		{name: "downstream NONE", downstream: TLSServerModeNone, upstream: TLSClientModeVerifyFull},
		{name: "upstream VERIFY_FULL", downstream: TLSServerModeTLS13, upstream: TLSClientModeVerifyFull},
		{name: "upstream VERIFY_CA", downstream: TLSServerModeTLS13, upstream: TLSClientModeVerifyCA},
		{name: "upstream INSECURE", downstream: TLSServerModeTLS13, upstream: TLSClientModeInsecure},
		{name: "upstream NONE", downstream: TLSServerModeTLS13, upstream: TLSClientModeNone},
	}

	for _, tt := range validTLSModes {
		t.Run("Valid web app TLS modes: "+tt.name, func(t *testing.T) {
			claims := validClaims
			claims.Resource.Type = ResourceTypeWebApp
			claims.Resource.GatewayMetadata.Downstream.TLSMode = tt.downstream
			claims.Resource.GatewayMetadata.Upstream.TLSMode = tt.upstream

			assert.NoError(t, claims.Validate())
		})
	}

	t.Run("Valid PostgreSQL claims", func(t *testing.T) {
		claims := validClaims
		claims.Resource.Type = ResourceTypePostgreSQL
		claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeNone
		claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
		claims.Resource.GatewayMetadata.Auths = Auths{{Type: AuthTypePassword, User: "viewer", Password: &PasswordAuth{Credential: "prod-viewer"}}}

		assert.NoError(t, claims.Validate())
	})

	tests := []struct {
		name                 string
		setupFn              func(*GATClaims)
		expectedError        error
		expectedErrorMessage string
	}{
		{
			name: "Missing token type",
			setupFn: func(claims *GATClaims) {
				claims.Type = ""
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"typ\"",
		},
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
			name: "Invalid token type",
			setupFn: func(claims *GATClaims) {
				claims.Type = "JWT"
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "token type is invalid \"JWT\"",
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
				claims.Resource.GatewayMetadata = GatewayMetadata{}
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\": 0",
		},
		{
			name: "Negative downstream port",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Downstream.Port = -1
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\": -1",
		},
		{
			name: "Downstream port out of range",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Downstream.Port = 65536
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.downstream.port\": 65536",
		},
		{
			name: "Missing upstream port",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata = GatewayMetadata{
					Downstream: Downstream{Port: 443},
				}
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.upstream.port\": 0",
		},
		{
			name: "Negative upstream port",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Upstream.Port = -1
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.upstream.port\": -1",
		},
		{
			name: "Upstream port out of range",
			setupFn: func(claims *GATClaims) {
				claims.Resource.GatewayMetadata.Upstream.Port = 65536
			},
			expectedError:        jwt.ErrTokenInvalidClaims,
			expectedErrorMessage: "invalid port \"resource.gateway_metadata.upstream.port\": 65536",
		},
		{
			name: "Missing web app downstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypeWebApp
				claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.downstream.tls_mode\": \"\"",
		},
		{
			name: "Invalid web app downstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypeWebApp
				claims.Resource.GatewayMetadata.Downstream.TLSMode = "TLS12"
				claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.downstream.tls_mode\": \"TLS12\"",
		},
		{
			name: "Missing web app upstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypeWebApp
				claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeTLS13
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.upstream.tls_mode\": \"\"",
		},
		{
			name: "Invalid web app upstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypeWebApp
				claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeTLS13
				claims.Resource.GatewayMetadata.Upstream.TLSMode = "VERIFY_NONE"
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.upstream.tls_mode\": \"VERIFY_NONE\"",
		},
		{
			name: "Missing PostgreSQL downstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypePostgreSQL
				claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.downstream.tls_mode\": \"\"",
		},
		{
			name: "Missing PostgreSQL upstream TLS mode",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypePostgreSQL
				claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeNone
			},
			expectedError:        errInvalidTLSMode,
			expectedErrorMessage: "invalid TLS mode \"resource.gateway_metadata.upstream.tls_mode\": \"\"",
		},
		{
			name: "PostgreSQL downstream TLS13",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypePostgreSQL
				claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeTLS13
				claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
			},
			expectedError:        errUnsupportedTLS,
			expectedErrorMessage: "\"resource.gateway_metadata.downstream.tls_mode\": \"TLS13\"",
		},
		{
			name: "Missing PostgreSQL auths",
			setupFn: func(claims *GATClaims) {
				claims.Resource.Type = ResourceTypePostgreSQL
				claims.Resource.GatewayMetadata.Downstream.TLSMode = TLSServerModeNone
				claims.Resource.GatewayMetadata.Upstream.TLSMode = TLSClientModeVerifyFull
			},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"resource.gateway_metadata.auths\"",
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

func TestAuths_Validate(t *testing.T) {
	validAuth := Auth{Type: AuthTypePassword, User: "viewer", Password: &PasswordAuth{Credential: "prod-viewer"}}

	t.Run("Valid auths", func(t *testing.T) {
		assert.NoError(t, Auths{validAuth}.Validate(TLSClientModeVerifyFull))
	})

	tests := []struct {
		name                 string
		auths                Auths
		expectedError        error
		expectedErrorMessage string
	}{
		{
			name:                 "Missing auths",
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"resource.gateway_metadata.auths\"",
		},
		{
			name:                 "Invalid auth",
			auths:                Auths{{Type: AuthTypePassword, User: "editor", Password: &PasswordAuth{}}},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "resource.gateway_metadata.auths[0]: token is missing required claim \"credential\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auths.Validate(TLSClientModeVerifyFull)

			require.ErrorIs(t, err, tt.expectedError)
			require.ErrorContains(t, err, tt.expectedErrorMessage)
		})
	}
}

func TestAuth_Validate(t *testing.T) {
	validAuths := []struct {
		name            string
		upstreamTLSMode TLSClientMode
		auth            Auth
	}{
		{
			name:            "password with upstream NONE",
			upstreamTLSMode: TLSClientModeNone,
			auth:            Auth{Type: AuthTypePassword, User: "viewer", Password: &PasswordAuth{Credential: "prod-viewer"}},
		},
		{
			name:            "AWS IAM with upstream VERIFY_FULL",
			upstreamTLSMode: TLSClientModeVerifyFull,
			auth:            Auth{Type: AuthTypeAWSIAM, User: "analytics", AWSIAM: &AWSIAMAuth{Region: "us-east-1"}},
		},
		{
			name:            "GCP IAM with upstream VERIFY_CA",
			upstreamTLSMode: TLSClientModeVerifyCA,
			auth:            Auth{Type: AuthTypeGCPIAM, User: "db@my-project.iam", GCPIAM: &GCPIAMAuth{}},
		},
	}

	for _, tt := range validAuths {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.auth.Validate(tt.upstreamTLSMode))
		})
	}

	tests := []struct {
		name                 string
		upstreamTLSMode      TLSClientMode
		auth                 Auth
		expectedError        error
		expectedErrorMessage string
	}{
		{
			name:                 "Missing user",
			upstreamTLSMode:      TLSClientModeVerifyFull,
			auth:                 Auth{Type: AuthTypeGCPIAM, GCPIAM: &GCPIAMAuth{}},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"user\"",
		},
		{
			name:                 "Invalid type",
			upstreamTLSMode:      TLSClientModeVerifyFull,
			auth:                 Auth{Type: "md5", User: "viewer"},
			expectedError:        errInvalidAuthType,
			expectedErrorMessage: "invalid auth type \"md5\"",
		},
		{
			name:                 "Password without credential",
			upstreamTLSMode:      TLSClientModeVerifyFull,
			auth:                 Auth{Type: AuthTypePassword, User: "viewer", Password: &PasswordAuth{}},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"credential\"",
		},
		{
			name:                 "AWS IAM without region",
			upstreamTLSMode:      TLSClientModeVerifyFull,
			auth:                 Auth{Type: AuthTypeAWSIAM, User: "analytics", AWSIAM: &AWSIAMAuth{}},
			expectedError:        jwt.ErrTokenRequiredClaimMissing,
			expectedErrorMessage: "\"region\"",
		},
		{
			name:                 "AWS IAM with upstream INSECURE",
			upstreamTLSMode:      TLSClientModeInsecure,
			auth:                 Auth{Type: AuthTypeAWSIAM, User: "analytics", AWSIAM: &AWSIAMAuth{Region: "us-east-1"}},
			expectedError:        errUnverifiedIAMUpstream,
			expectedErrorMessage: "\"resource.gateway_metadata.upstream.tls_mode\": \"INSECURE\"",
		},
		{
			name:                 "GCP IAM with upstream NONE",
			upstreamTLSMode:      TLSClientModeNone,
			auth:                 Auth{Type: AuthTypeGCPIAM, User: "db@my-project.iam", GCPIAM: &GCPIAMAuth{}},
			expectedError:        errUnverifiedIAMUpstream,
			expectedErrorMessage: "\"resource.gateway_metadata.upstream.tls_mode\": \"NONE\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auth.Validate(tt.upstreamTLSMode)

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
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		jsonBytes, err := pubKey.MarshalJSON()

		require.NoError(t, err)
		require.JSONEq(t, "\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFelBCVWRDUVRDTC85eWhPUzI3S1AyWTN1cjR5aApYd1N6enhZOGJhT3hESlIyVHYzL3pMOW1JWExZSld0NzlHeE5hL0h2MWFJRi9SS2hZdHRPc0JvaUZnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"", string(jsonBytes))
	})

	t.Run("Invalid public key", func(t *testing.T) {
		pubKey := &PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
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

func TestGatewayMetadata_UnmarshalTLSModes(t *testing.T) {
	var metadata GatewayMetadata

	err := json.Unmarshal([]byte(`{"downstream": {"port": 443, "tls_mode": "TLS13"}, "upstream": {"port": 5000, "tls_mode": "VERIFY_CA"}}`), &metadata)
	require.NoError(t, err)

	assert.Equal(t, TLSServerModeTLS13, metadata.Downstream.TLSMode)
	assert.Equal(t, TLSClientModeVerifyCA, metadata.Upstream.TLSMode)
}

func TestAuth_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		json string
		want Auth
	}{
		{
			name: "Password",
			json: `{"type": "password", "user": "viewer", "credential": "prod-viewer"}`,
			want: Auth{Type: AuthTypePassword, User: "viewer", Password: &PasswordAuth{Credential: "prod-viewer"}},
		},
		{
			name: "AWS IAM",
			json: `{"type": "aws_iam", "user": "analytics", "region": "us-east-1", "assume_role_arn": "arn:aws:iam::123456789012:role/gateway-db"}`,
			want: Auth{Type: AuthTypeAWSIAM, User: "analytics", AWSIAM: &AWSIAMAuth{Region: "us-east-1", AssumeRoleARN: "arn:aws:iam::123456789012:role/gateway-db"}},
		},
		{
			name: "GCP IAM",
			json: `{"type": "gcp_iam", "user": "db@my-project.iam", "impersonate_service_account": "db@my-project.iam.gserviceaccount.com"}`,
			want: Auth{Type: AuthTypeGCPIAM, User: "db@my-project.iam", GCPIAM: &GCPIAMAuth{ImpersonateServiceAccount: "db@my-project.iam.gserviceaccount.com"}},
		},
		{
			name: "Unknown type",
			json: `{"type": "md5", "user": "viewer"}`,
			want: Auth{Type: "md5", User: "viewer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var auth Auth

			err := json.Unmarshal([]byte(tt.json), &auth)
			require.NoError(t, err)

			assert.Equal(t, tt.want, auth)

			jsonBytes, err := json.Marshal(auth)
			require.NoError(t, err)

			assert.JSONEq(t, tt.json, string(jsonBytes))
		})
	}

	t.Run("Invalid JSON value", func(t *testing.T) {
		var auth Auth

		err := json.Unmarshal([]byte(`3`), &auth)

		require.ErrorContains(t, err, "cannot unmarshal number")
	})
}
