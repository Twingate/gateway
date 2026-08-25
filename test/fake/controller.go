// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package fake

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"gateway/internal/token"
	"gateway/test/data"
)

const keyID = "1"
const issuer = "twingate-local"

type requestBody struct {
	ClientPublicKey *token.PublicKey `json:"clientPublicKey,omitempty"`
	User            *token.User      `json:"user,omitempty"`
	Device          *token.Device    `json:"device,omitempty"`
	Resource        *token.Resource  `json:"resource,omitempty"`
}

// NewController creates an HTTP server that simulates a Twingate controller.
//
// It has two endpoints:
// - /api/v1/jwk/ec: Returns the JWK Set that is used to verify GAT tokens.
// - /api/v1/gat: Returns a GAT token for a client.
func NewController(network string, port int) *httptest.Server {
	logger := zap.Must(zap.NewDevelopment()).Named("controller")

	controllerKey, _ := ReadECKey(data.ControllerKey)

	jwkSetJSON, err := createJWKSet(controllerKey)
	if err != nil {
		logger.Error("Failed to create JWK Set", zap.Error(err))

		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/jwk/ec", func(writer http.ResponseWriter, _request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		_, err := writer.Write(jwkSetJSON)
		if err != nil {
			logger.Error("Failed to respond with JWK Set JSON", zap.Error(err))

			return
		}

		logger.Info("JWK returned")
	})
	mux.HandleFunc("/api/v1/gat", func(writer http.ResponseWriter, request *http.Request) {
		// Read and parse the request body
		var requestBody requestBody

		decoder := json.NewDecoder(request.Body)
		if err := decoder.Decode(&requestBody); err != nil {
			logger.Error("Failed to parse request body", zap.Error(err))
			writer.WriteHeader(http.StatusBadRequest)

			return
		}

		logger.Info("Received GAT request", zap.Any("user", &requestBody.User), zap.Any("device", &requestBody.Device), zap.Any("resource", &requestBody.Resource))

		claims := token.GATClaims{
			Issuer:          issuer,
			Audience:        jwt.ClaimStrings([]string{network}),
			IssuedAt:        jwt.NewNumericDate(time.Now()),
			ExpiresAt:       jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Type:            "GAT",
			Version:         "1",
			RenewAt:         jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ClientPublicKey: *requestBody.ClientPublicKey,
			User:            *requestBody.User,
			Device:          *requestBody.Device,
			Resource:        *requestBody.Resource,
		}

		token := &jwt.Token{
			Header: map[string]any{
				"typ": "JWT",
				"alg": jwt.SigningMethodES256.Alg(),
				"kid": keyID,
			},
			Claims: claims,
			Method: jwt.SigningMethodES256,
		}

		tokenString, err := token.SignedString(controllerKey)
		if err != nil {
			logger.Error("Failed to sign JWT", zap.Error(err))
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		_, err = writer.Write([]byte(tokenString))
		if err != nil {
			logger.Error("Failed to respond with JWT", zap.Error(err))

			return
		}

		logger.Info("JWT generated")
	})

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Error("Failed to listen on port", zap.Error(err))

		return nil
	}

	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()

	return server
}

func createJWKSet(controllerKey *ecdsa.PrivateKey) (json.RawMessage, error) {
	jwkSet := jwkset.NewMemoryStorage()

	metadata := jwkset.JWKMetadataOptions{
		KID: keyID,
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}

	jwk, err := jwkset.NewJWKFromKey(controllerKey, options)
	if err != nil {
		return nil, err
	}

	err = jwkSet.KeyWrite(context.Background(), jwk)
	if err != nil {
		return nil, err
	}

	publicKeyJSON, err := jwkSet.JSONPublic(context.Background())
	if err != nil {
		return nil, err
	}

	return publicKeyJSON, nil
}
