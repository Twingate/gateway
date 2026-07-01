// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"gateway/internal/token"
)

// AuthHeaderKey is the header that contains the auth token.
const AuthHeaderKey string = "Proxy-Authorization"

// AuthSignatureHeaderKey is the header that contains the signature of the token for Proof-of-Possession.
const AuthSignatureHeaderKey string = "X-Token-Signature"

// ConnIDHeaderKey is the header that contains the Connection ID.
const ConnIDHeaderKey string = "X-Connection-Id"

type Info struct {
	Address string
	Claims  *token.GATClaims
	ConnID  string
	Token   string
}

type HTTPError struct {
	Err     error
	Code    int // HTTP status code
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

type Validator interface {
	ParseConnect(req *http.Request, ekm []byte) (connectInfo Info, err error)
}

type MessageValidator struct {
	TokenParser *token.Parser
}

func (v *MessageValidator) ParseConnect(req *http.Request, ekm []byte) (connectInfo Info, err error) {
	if req.Method != http.MethodConnect {
		// did not receive CONNECT, return 405 Method Not Allowed
		return Info{
				Claims: nil,
				ConnID: "",
			}, &HTTPError{
				Code:    http.StatusMethodNotAllowed,
				Message: "expected CONNECT request got " + req.Method,
				Err:     nil,
			}
	}

	connID := req.Header.Get(ConnIDHeaderKey)

	authHeader := req.Header.Get(AuthHeaderKey)

	bearerToken, tokenErr := token.ParseBearerToken(authHeader)
	if tokenErr != nil {
		// did not receive identity header in CONNECT, return 407 Proxy Authentication Required
		return Info{
				Claims: nil,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusProxyAuthRequired,
				Message: fmt.Sprintf("missing identity header in CONNECT %v", tokenErr),
				Err:     tokenErr,
			}
	}

	gatClaims := &token.GATClaims{}

	_, tokenErr = v.TokenParser.ParseWithClaims(bearerToken, gatClaims)
	if tokenErr != nil {
		return Info{
				Claims: nil,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("failed to parse token with error %v", tokenErr),
				Err:     tokenErr,
			}
	}

	// parse signature header for Proof-of-Possession
	signatureB64 := req.Header.Get(AuthSignatureHeaderKey)

	clientSig, tokenErr := base64.StdEncoding.DecodeString(signatureB64)
	if tokenErr != nil {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("failed to decode client signature with error %v", tokenErr),
				Err:     tokenErr,
			}
	}

	// verify signature
	hashed := sha256.Sum256(ekm)

	ok := ecdsa.VerifyASN1(&gatClaims.ClientPublicKey.PublicKey, hashed[:], clientSig)
	if !ok {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusUnauthorized,
				Message: "failed to verify signature",
				Err:     nil,
			}
	}

	// verify address in CONNECT with the GAT token
	address := req.RequestURI

	host, port, hostErr := net.SplitHostPort(address)
	if hostErr != nil {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("failed to parse CONNECT destination: %v", hostErr),
				Err:     hostErr,
			}
	}

	if !matchResourceAddress(gatClaims.Resource.Address, host) {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("failed to verify CONNECT destination: %s with token resource address %s", host, gatClaims.Resource.Address),
				Err:     nil,
			}
	}

	// Both ports are validated for presence and range when the token is parsed
	// so it is guaranteed to be within the valid range here.
	downstreamPort := gatClaims.Resource.GatewayMetadata.Downstream.Port
	upstreamPort := gatClaims.Resource.GatewayMetadata.Upstream.Port

	requestedPort, portErr := strconv.Atoi(port)
	if portErr != nil {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("failed to parse CONNECT destination port: %v", portErr),
				Err:     portErr,
			}
	}

	if requestedPort != downstreamPort {
		return Info{
				Claims: gatClaims,
				ConnID: connID,
			}, &HTTPError{
				Code:    http.StatusForbidden,
				Message: fmt.Sprintf("failed to verify CONNECT destination port: %s with token downstream port %d", port, downstreamPort),
				Err:     nil,
			}
	}

	// rewrite the destination port to the upstream port for backend forwarding
	address = net.JoinHostPort(host, strconv.Itoa(upstreamPort))

	return Info{
		Address: address,
		Claims:  gatClaims,
		ConnID:  connID,
		Token:   bearerToken,
	}, nil
}

var validDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// matchResourceAddress checks whether host matches the resource address pattern.
// Supports exact match and RFC 6125 wildcard matching: *.example.com matches
// api.example.com but not example.com or foo.bar.example.com.
func matchResourceAddress(pattern, host string) bool {
	if strings.EqualFold(pattern, host) {
		return true
	}

	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := pattern[1:]
	if len(host) <= len(suffix) || !strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix)) {
		return false
	}

	label := host[:len(host)-len(suffix)]

	return validDNSLabel.MatchString(label)
}
