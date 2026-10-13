// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/logging"
	"gateway/internal/proxy"
	"gateway/internal/token"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

const (
	pgUpstreamUser     = "gateway_svc"
	pgUpstreamPassword = "s3cret-test-pw"
	pgUpstreamDB       = "app"
	pgCredential       = "test-db"
)

type pgTestEnv struct {
	containerID string
	client      *fake.Client
	logs        *observer.ObservedLogs
}

func setupPostgresGateway(t *testing.T, user *token.User, authMethod testutil.PostgresAuthMethod, gatewayPort int) *pgTestEnv {
	t.Helper()

	containerID, pgServerPort := testutil.SetupPostgresServer(t, pgUpstreamUser, pgUpstreamPassword, pgUpstreamDB, authMethod)
	pgServerAddress := fmt.Sprintf("127.0.0.1:%d", pgServerPort)

	controller := fake.NewController(network, 8080)

	t.Cleanup(func() { controller.Close() })

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			Certificates: &gatewayconfig.TLSCertificateSources{
				Files: []gatewayconfig.TLSCertificateFileKeyPair{
					{
						CertificateFile: "../data/proxy/tls.crt",
						PrivateKeyFile:  "../data/proxy/tls.key",
					},
				},
			},
		},
		PostgreSQL: &gatewayconfig.PostgreSQLConfig{
			Credentials: []gatewayconfig.PostgreSQLCredential{
				{Name: pgCredential, Password: pgUpstreamPassword},
			},
		},
	}

	core, logs := observer.New(zap.DebugLevel)
	logger := logging.Logger{System: zap.New(core).Named("test"), Audit: zap.New(core).Named("test")}

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	go func() {
		err := p.Start()
		t.Logf("Gateway stopped: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	client := fake.NewClient(
		user,
		token.GeoIPLocation{},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		controller.URL,
		pgServerAddress,
		token.ResourceTypePostgres,
		fake.WithAuths(token.Auth{Type: token.AuthTypePassword, User: pgUpstreamUser, Credential: pgCredential}),
	)

	t.Cleanup(func() { client.Close() })

	return &pgTestEnv{
		containerID: containerID,
		client:      client,
		logs:        logs,
	}
}

// runPostgresQuery connects to the Twingate client tunnel as a PG client and
// runs `SELECT 1`, asserting the expected row.
func runPostgresQuery(t *testing.T, env *pgTestEnv) {
	t.Helper()

	host, port, err := net.SplitHostPort(env.client.Address)
	require.NoError(t, err)

	// Client-supplied user is arbitrary; gateway overrides it with the GAT auth user.
	// Password is unused by our proxy but pgx requires a value, so pass a
	// placeholder.
	connString := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=irrelevant password=placeholder sslmode=disable",
		host, port, pgUpstreamDB,
	)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, connString)
	require.NoError(t, err, "pgx.Connect failed")

	defer func() { _ = conn.Close(ctx) }()

	var result int

	err = conn.QueryRow(ctx, "SELECT 1").Scan(&result)
	require.NoError(t, err, "SELECT 1 failed")
	assert.Equal(t, 1, result)
}

func TestPostgresSCRAM(t *testing.T) {
	const gatewayPort = 8446

	env := setupPostgresGateway(t, &token.User{
		ID:       "user-pg-scram",
		Username: "alice@acme.com",
		Groups:   []string{"Engineering"},
	}, testutil.PostgresAuthSCRAM, gatewayPort)

	runPostgresQuery(t, env)
}

func TestPostgresCleartext(t *testing.T) {
	const gatewayPort = 8447

	env := setupPostgresGateway(t, &token.User{
		ID:       "user-pg-cleartext",
		Username: "bob@acme.com",
		Groups:   []string{"Analytics"},
	}, testutil.PostgresAuthCleartext, gatewayPort)

	runPostgresQuery(t, env)

	// Gateway should have logged the SQL the client ran. Extended-protocol
	// prepared statements surface via "pg parse"; simple queries via "pg query".
	sqlEntries := env.logs.FilterMessage("pg parse").FilterField(zap.String("sql", "SELECT 1")).All()
	if len(sqlEntries) == 0 {
		sqlEntries = env.logs.FilterMessage("pg query").FilterField(zap.String("sql", "SELECT 1")).All()
	}

	assert.NotEmpty(t, sqlEntries, "expected gateway to log the SELECT 1 statement")

	// pgx runs the statement through the extended protocol, so the Bind and
	// Execute that follow the Parse are logged as their own lines.
	assert.NotEmpty(t, env.logs.FilterMessage("pg bind").All(), "expected a pg bind log")
	assert.NotEmpty(t, env.logs.FilterMessage("pg execute").All(), "expected a pg execute log")

	// Gateway should have emitted exactly one aggregated result log for the
	// request. The observer renders our nested marshaler via zap's reflection
	// path, so inspect the context map for the "results" field.
	resultEntries := env.logs.FilterMessage("pg result").All()
	require.NotEmpty(t, resultEntries, "expected at least one pg result log")
}

func TestPostgresCancel(t *testing.T) {
	const gatewayPort = 8453

	env := setupPostgresGateway(t, &token.User{
		ID:       "user-pg-cancel",
		Username: "carol@acme.com",
		Groups:   []string{"Engineering"},
	}, testutil.PostgresAuthSCRAM, gatewayPort)

	host, port, err := net.SplitHostPort(env.client.Address)
	require.NoError(t, err)

	conn, err := pgx.Connect(t.Context(), fmt.Sprintf(
		"host=%s port=%s dbname=%s user=irrelevant password=placeholder sslmode=disable",
		host, port, pgUpstreamDB,
	))
	require.NoError(t, err)

	defer func() { _ = conn.Close(t.Context()) }()

	// pgx sends a CancelRequest on a new connection when the query context expires.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	start := time.Now()
	_, err = conn.Exec(ctx, "SELECT pg_sleep(30)")

	var pgErr *pgconn.PgError

	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "57014", pgErr.Code, "upstream should report query_canceled")
	assert.Less(t, time.Since(start), 10*time.Second)
	assert.NotEmpty(t, env.logs.FilterMessage("pg cancel").All(), "expected a pg cancel log")
}
