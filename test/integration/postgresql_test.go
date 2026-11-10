// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/proxy"
	"gateway/internal/token"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

const (
	postgreSQLGatewayPort = 8451
	postgreSQLCredential  = "integration-test"
)

func TestPostgreSQL(t *testing.T) {
	_, serverPort := testutil.SetupPostgreSQLServer(t)

	controller := fake.NewController(network, 8080)

	t.Cleanup(func() { controller.Close() })

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        postgreSQLGatewayPort,
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
				{Name: postgreSQLCredential, Password: testutil.PostgreSQLPassword},
			},
		},
		UpstreamTrustedCABundles: []gatewayconfig.UpstreamTrustedCABundle{{File: testutil.PostgreSQLCertificateFile}},
	}

	logger, logs := testutil.NewObservedLogger()

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, postgreSQLGatewayPort)

	auths := token.Auths{{
		Type:     token.AuthTypePassword,
		User:     testutil.PostgreSQLUsername,
		Password: &token.PasswordAuth{Credential: postgreSQLCredential},
	}}

	expectedUser := map[string]any{
		"id":       "user-postgresql-1",
		"username": "alex@acme.com",
		"groups":   []any{"OnCall", "Engineering"},
	}

	for _, tt := range []struct {
		name    string
		tlsMode token.TLSClientMode
	}{
		{name: "plaintext", tlsMode: token.TLSClientModeNone},
		{name: "tls", tlsMode: token.TLSClientModeVerifyFull},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := testutil.NewPostgreSQLUser(
				&token.User{ID: "user-postgresql-1", Username: "alex@acme.com", Groups: []string{"OnCall", "Engineering"}},
				postgreSQLGatewayPort,
				fmt.Sprintf("127.0.0.1:%d", serverPort),
				controller.URL,
				auths,
				fake.WithUpstreamTLSMode(tt.tlsMode),
			)

			t.Cleanup(func() { user.Close() })

			conn, err := pgx.Connect(t.Context(), fmt.Sprintf("postgres://client:unused@%s/%s", user.Address, testutil.PostgreSQLDatabase))
			require.NoError(t, err, "failed to connect to PostgreSQL through the Gateway")

			t.Cleanup(func() { _ = conn.Close(t.Context()) })

			expectedDatabase := map[string]any{
				"db": map[string]any{
					"user": testutil.PostgreSQLUsername,
					"name": testutil.PostgreSQLDatabase,
				},
				"process_id": conn.PgConn().PID(),
			}

			require.Eventually(t, func() bool {
				return logs.FilterMessage("PostgreSQL connection established").FilterField(zap.Uint32("process_id", conn.PgConn().PID())).Len() == 1
			}, 5*time.Second, 10*time.Millisecond)

			t.Run("query", func(t *testing.T) {
				const (
					query = "SELECT current_user, current_database(), ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
					// pgx names the statements it caches after a hash of their SQL.
					statementName = "stmtcache_56407bda974dc11bdff7bbcd045e9d693865d09f24a6b6e0"
				)

				seen := logs.Len()

				var (
					currentUser, currentDatabase string
					ssl                          bool
				)

				err := conn.QueryRow(t.Context(), query).Scan(&currentUser, &currentDatabase, &ssl)
				require.NoError(t, err)

				assert.Equal(t, testutil.PostgreSQLUsername, currentUser)
				assert.Equal(t, testutil.PostgreSQLDatabase, currentDatabase)
				assert.Equal(t, tt.tlsMode != token.TLSClientModeNone, ssl)

				testutil.AssertLogsForPostgreSQLSession(t, logs.All()[seen:], expectedUser, expectedDatabase, []testutil.PostgreSQLAuditLog{
					{Message: "pg parse", Fields: map[string]any{"statement_name": statementName, "sql": query}},
					{Message: "pg completed", Fields: map[string]any{}},
					{Message: "pg bind", Fields: map[string]any{"statement_name": statementName, "portal_name": "", "parameters": []any{}}},
					{Message: "pg execute", Fields: map[string]any{"portal_name": "", "max_rows": uint32(0)}},
					{Message: "pg result", Fields: map[string]any{"command": "SELECT", "row_count": int64(1)}},
					{Message: "pg completed", Fields: map[string]any{}},
				})
			})

			t.Run("copy", func(t *testing.T) {
				seen := logs.Len()

				_, err := conn.Exec(t.Context(), "CREATE TEMPORARY TABLE items (id int, name text)")
				require.NoError(t, err)

				copied, err := conn.PgConn().CopyFrom(t.Context(), strings.NewReader("1\tone\n2\ttwo\n"), "COPY items FROM STDIN")
				require.NoError(t, err)
				assert.EqualValues(t, 2, copied.RowsAffected())

				var out bytes.Buffer

				_, err = conn.PgConn().CopyTo(t.Context(), &out, "COPY items TO STDOUT")
				require.NoError(t, err)
				assert.Equal(t, "1\tone\n2\ttwo\n", out.String())

				testutil.AssertLogsForPostgreSQLSession(t, logs.All()[seen:], expectedUser, expectedDatabase, []testutil.PostgreSQLAuditLog{
					{Message: "pg query", Fields: map[string]any{"sql": "CREATE TEMPORARY TABLE items (id int, name text)"}},
					{Message: "pg result", Fields: map[string]any{"command": "CREATE TABLE"}},
					{Message: "pg completed", Fields: map[string]any{}},
					{Message: "pg query", Fields: map[string]any{"sql": "COPY items FROM STDIN"}},
					{Message: "pg result", Fields: map[string]any{"command": "COPY", "row_count": int64(2)}},
					{Message: "pg completed", Fields: map[string]any{}},
					{Message: "pg query", Fields: map[string]any{"sql": "COPY items TO STDOUT"}},
					{Message: "pg result", Fields: map[string]any{"command": "COPY", "row_count": int64(2)}},
					{Message: "pg completed", Fields: map[string]any{}},
				})
			})

			t.Run("cancel", func(t *testing.T) {
				const query = "SELECT pg_sleep(30)"

				seen := logs.Len()
				queryDone := make(chan error, 1)

				go func() {
					_, err := conn.Exec(t.Context(), query)
					queryDone <- err
				}()

				// PostgreSQL ignores a cancel that reaches an idle backend, so wait until the Gateway relays the query.
				require.Eventually(t, func() bool {
					return logs.FilterMessage("pg query").FilterField(zap.String("sql", query)).FilterField(zap.Uint32("process_id", conn.PgConn().PID())).Len() == 1
				}, 5*time.Second, 10*time.Millisecond)

				require.NoError(t, conn.PgConn().CancelRequest(t.Context()))

				var pgErr *pgconn.PgError

				select {
				case err := <-queryDone:
					require.ErrorAs(t, err, &pgErr)
					assert.Equal(t, "57014", pgErr.Code, "query_canceled")
				case <-time.After(10 * time.Second):
					t.Fatal("the query was not cancelled")
				}

				entries := logs.All()[seen:]

				testutil.AssertLogsForPostgreSQLSession(t, entries, expectedUser, expectedDatabase, []testutil.PostgreSQLAuditLog{
					{Message: "pg query", Fields: map[string]any{"sql": query}},
					{Message: "pg result", Fields: map[string]any{"error_code": "57014", "error_message": "canceling statement due to user request"}},
					{Message: "pg completed", Fields: map[string]any{}},
				})
				testutil.AssertLogsForPostgreSQLCancel(t, entries, expectedUser, conn.PgConn().PID())
			})

			require.NoError(t, conn.Close(t.Context()))

			require.Eventually(t, func() bool {
				return logs.FilterMessage("PostgreSQL connection closed").FilterField(zap.Uint32("process_id", conn.PgConn().PID())).Len() == 1
			}, 5*time.Second, 10*time.Millisecond)
		})
	}
}
