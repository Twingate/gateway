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

	address, httpErr := resolveUpstreamAddress(host, port, gatClaims.Resource)
	if httpErr != nil {
		return Info{
			Claims: gatClaims,
			ConnID: connID,
		}, httpErr
	}

	return Info{
		Address: address,
		Claims:  gatClaims,
		ConnID:  connID,
		Token:   bearerToken,
	}, nil
}

// resolveUpstreamAddress verifies the CONNECT destination against the GAT
// resource and maps it to the upstream address for backend forwarding: a host
// matching the resource alias maps to the resource address, and the downstream
// port maps to the upstream port. Both ports are validated for presence and
// range when the token is parsed.
func resolveUpstreamAddress(host, port string, resource token.Resource) (string, *HTTPError) {
	switch {
	case matchResourceAddress(resource.Address, host):
	case matchResourceAlias(resource.Alias, host):
		host = resource.Address
	default:
		return "", &HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("CONNECT destination address %s does not match token resource address %s", host, resource.Address),
			Err:     nil,
		}
	}

	requestedPort, err := strconv.Atoi(port)
	if err != nil {
		return "", &HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("failed to parse CONNECT destination port: %v", err),
			Err:     err,
		}
	}

	metadata := resource.GatewayMetadata
	if requestedPort != metadata.Downstream.Port {
		return "", &HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("CONNECT destination port %d does not match token downstream port %d", requestedPort, metadata.Downstream.Port),
			Err:     nil,
		}
	}

	return net.JoinHostPort(host, strconv.Itoa(metadata.Upstream.Port)), nil
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

// matchResourceAlias checks whether host matches the resource alias.
func matchResourceAlias(alias, host string) bool {
	return alias != "" && strings.EqualFold(alias, host)
}
