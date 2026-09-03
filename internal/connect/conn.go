// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"gateway/internal/token"
)

const healthCheckPath = "/healthz"

const (
	keyingMaterialLabel  = "EXPERIMENTAL_twingate_gat"
	keyingMaterialLength = 32
)

const defaultTimeout = 10 * time.Second

func httpResponseString(httpCode int) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", httpCode, http.StatusText(httpCode))
}

// Conn is a custom connection that wraps the underlying TCP net.Conn, handling downstream
// proxy (Twingate Client)'s authentication via the initial CONNECT message.
type Conn interface {
	net.Conn
	GATClaims() *token.GATClaims
	GetID() string
	// GetRequestedHost returns the host from the CONNECT target.
	GetRequestedHost() string
	GetUpstreamAddress() string
	GetToken() string
	Authenticate() error
	UpgradeToTLS() error

	Close() error
}

type ProxyConn struct {
	net.Conn

	TLSConfig        *tls.Config
	CertManager      *CertManager
	ConnectValidator Validator
	Logger           *zap.Logger

	ID            string
	RequestedHost string
	UpstreamHost  string
	Claims        *token.GATClaims
	Token         string

	Timer *time.Timer
	Mu    sync.Mutex

	tracker *ProxyConnMetricsTracker
	once    sync.Once
}

func NewProxyConn(
	conn net.Conn,
	tlsConfig *tls.Config,
	certManager *CertManager,
	validator Validator,
	logger *zap.Logger,
	metrics *ProxyConnMetrics,
) *ProxyConn {
	return &ProxyConn{
		Conn:             conn,
		TLSConfig:        tlsConfig,
		CertManager:      certManager,
		ConnectValidator: validator,
		Logger:           logger,
		tracker:          NewProxyConnMetricsTracker(ConnCategoryUnknown, metrics),
	}
}

func (p *ProxyConn) Close() error {
	p.Mu.Lock()
	defer p.Mu.Unlock()

	defer p.once.Do(func() {
		p.tracker.RecordConnMetrics()
	})

	if p.Timer != nil {
		p.Timer.Stop()
	}

	return p.Conn.Close()
}

func (p *ProxyConn) GATClaims() *token.GATClaims {
	return p.Claims
}

func (p *ProxyConn) GetID() string {
	return p.ID
}

func (p *ProxyConn) GetRequestedHost() string {
	return p.RequestedHost
}

func (p *ProxyConn) GetUpstreamAddress() string {
	upstreamPort := p.Claims.Resource.GatewayMetadata.Upstream.Port

	return net.JoinHostPort(p.UpstreamHost, strconv.Itoa(upstreamPort))
}

func (p *ProxyConn) GetToken() string {
	return p.Token
}

// Authenticate sets up TLS and processes the CONNECT message for authentication.
func (p *ProxyConn) Authenticate() error {
	_ = p.SetDeadline(time.Now().Add(defaultTimeout))

	defer func() {
		_ = p.SetDeadline(time.Time{})
	}()

	// Establish TLS connection with the downstream proxy
	tlsConnectConn := tls.Server(p.Conn, p.TLSConfig)

	if err := tlsConnectConn.Handshake(); err != nil {
		p.Logger.Error("failed to perform TLS handshake", zap.Error(err))

		return err
	}

	// Replace the underlying connection with the downstream proxy TLS connection
	p.Conn = tlsConnectConn

	// parse HTTP request
	bufReader := bufio.NewReader(tlsConnectConn)

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		p.Logger.Error("failed to parse HTTP request", zap.Error(err))

		responseStr := "HTTP/1.1 400 Bad Request\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.Logger.Error("failed to write response", zap.Error(writeErr))

			return writeErr
		}

		return err
	}

	// Health check request
	if isHealthCheckRequest(req) {
		p.tracker.ConnCategory = ConnCategoryHealth

		responseStr := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

		_, writeErr := tlsConnectConn.Write([]byte(responseStr))
		if writeErr != nil {
			p.Logger.Error("failed to write response", zap.Error(writeErr))

			return writeErr
		}

		return io.EOF
	}

	p.tracker.ConnCategory = ConnCategoryProxy

	// get the keying material for the TLS session
	ekm, err := ExportKeyingMaterial(tlsConnectConn)
	if err != nil {
		p.Logger.Error("failed to get keying material", zap.Error(err))

		return err
	}

	// Parse and validate HTTP request, expecting CONNECT with
	// valid token and signature
	httpCode := http.StatusOK

	connectInfo, err := p.ConnectValidator.ParseConnect(req, ekm)
	if err != nil {
		if httpErr, ok := errors.AsType[*HTTPError](err); ok {
			httpCode = httpErr.Code
		} else {
			p.Logger.Error("failed to parse CONNECT:", zap.Error(err))

			httpCode = http.StatusBadRequest
		}
	}

	if connectInfo.Claims != nil {
		p.Logger = p.Logger.With(
			zap.Object("user", connectInfo.Claims.User),
		)
	}

	p.Logger = p.Logger.With(
		zap.String("conn_id", connectInfo.ConnID),
	)

	response := httpResponseString(httpCode)

	_, writeErr := tlsConnectConn.Write([]byte(response))
	if writeErr != nil {
		p.Logger.Error("failed to write response", zap.Error(writeErr))

		return writeErr
	}

	if err != nil {
		p.Logger.Error("failed to serve request", zap.Error(err))

		return err
	}

	p.tracker.RecordConnectMetrics(httpCode)

	p.Logger.Info("Authenticated connection",
		zap.String("resource_type", string(connectInfo.Claims.Resource.Type)),
		zap.String("resource_address", connectInfo.Claims.Resource.Address),
	)
	p.setConnectInfo(connectInfo)

	return nil
}

func (p *ProxyConn) UpgradeToTLS() error {
	tlsConn := tls.Server(p.Conn, p.getTLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		p.Logger.Error("failed to upgrade TLS", zap.Error(err))

		return err
	}

	// Replace the underlying connection with the downstream client TLS connection
	p.Conn = tlsConn

	return nil
}

func (p *ProxyConn) getTLSConfig() *tls.Config {
	tlsConfig := p.TLSConfig.Clone()
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := p.CertManager.GetCertificateForHost(hello, p.RequestedHost, p.Claims.Resource.Aliases...)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate for %q: %w", p.RequestedHost, err)
		}

		return cert, nil
	}

	return tlsConfig
}

func (p *ProxyConn) setConnectInfo(connectInfo Info) {
	p.ID = connectInfo.ConnID
	p.RequestedHost = connectInfo.RequestedHost
	p.UpstreamHost = connectInfo.UpstreamHost
	p.Claims = connectInfo.Claims
	p.Token = connectInfo.Token
	p.Timer = time.AfterFunc(time.Until(connectInfo.Claims.ExpiresAt.Time), func() {
		_ = p.Close()
	})
}

func ExportKeyingMaterial(conn *tls.Conn) ([]byte, error) {
	cs := conn.ConnectionState()

	return cs.ExportKeyingMaterial(keyingMaterialLabel, nil, keyingMaterialLength)
}

func isHealthCheckRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == healthCheckPath
}
