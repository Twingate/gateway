// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	gatewayconfig "gateway/internal/config"
	"gateway/internal/proxy"
	"gateway/internal/sessionrecorder"
	"gateway/internal/token"
	"gateway/test/fake"
	"gateway/test/integration/testutil"
)

const numUsers = 10

// TestConcurrentUsers tests that multiple users can access the gateway concurrently
// and that their identities are correctly forwarded to the Kubernetes API server and logged.
//
// Each user run its own goroutine. A list of pre-defined commands is shuffled and run sequentially.
// The output and audit log of each command is asserted.
func TestConcurrentUsers(t *testing.T) {
	const gatewayPort = 8444

	kindKubectl, kindKubeConfig, kindBearerToken := testutil.SetupKinD(t)

	kindURL, err := url.Parse(kindKubeConfig.Host)
	require.NoError(t, err, "failed to parse API server URL")

	// Start the Controller
	controller := fake.NewController(network, 8080)
	defer controller.Close()

	t.Log("Controller is serving at", controller.URL)

	config := gatewayconfig.Config{
		Twingate: gatewayconfig.TwingateConfig{
			Network: network,
			Host:    host,
		},
		Port:        gatewayPort,
		MetricsPort: 0,
		TLS: gatewayconfig.TLSConfig{
			CertificateFile: "../data/proxy/tls.crt",
			PrivateKeyFile:  "../data/proxy/tls.key",
		},
		Kubernetes: &gatewayconfig.KubernetesConfig{
			Upstreams: []gatewayconfig.KubernetesUpstream{
				{
					Name:        "kind-cluster",
					BearerToken: kindBearerToken,
					CAFile:      "../data/api_server/tls.crt",
				},
			},
		},
	}

	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Named("test")

	p, err := proxy.NewProxy(&config, prometheus.NewRegistry(), logger)
	require.NoError(t, err, "failed to create proxy")

	// Start the Gateway
	go func() {
		err := p.Start()
		t.Logf("Failed to start Gateway: %v", err)
	}()

	testutil.GatewayHealthCheck(t, gatewayPort)

	var (
		users      = make([]*testutil.User, 0, numUsers)
		usersNames = make([]string, 0, numUsers)
	)

	for i := range numUsers {
		user, err := testutil.NewUser(
			&token.User{
				ID:       fmt.Sprintf("user-%d", i+1),
				Username: fmt.Sprintf("user-%d@acme.com", i+1),
				Groups:   []string{},
			},
			gatewayPort,
			kindURL.Host,
			controller.URL,
		)
		require.NoError(t, err, "failed to create user %d", i+1)

		users = append(users, user)
		usersNames = append(usersNames, user.Username)
	}

	defer func() {
		for _, user := range users {
			user.Close()
		}
	}()

	testutil.CreateK8sRoleBinding(t, kindKubectl, usersNames)

	wg := sync.WaitGroup{}

	for _, user := range users {
		wg.Go(func() {
			expectedUser := map[string]any{
				"id":       user.ID,
				"username": user.Username,
				"groups":   []any{},
			}

			commands := []command{
				{
					name: "whoami",
					args: []string{"auth", "whoami", "-o", "json"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						testutil.AssertWhoAmI(t, output, user.Username, []string{"system:authenticated"})
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForREST(t, logs, "/apis/authentication.k8s.io/v1/selfsubjectreviews", expectedUser, http.StatusCreated)
					},
				},
				{
					name:           "get-pods",
					args:           []string{"get", "pods", "-o", "json"},
					assertOutputFn: testutil.AssertGetPods,
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()
						testutil.AssertLogsForREST(t, logs, "/api/v1/namespaces/default/pods?limit=500", expectedUser, http.StatusOK)
					},
				},
				{
					name: "exec-sleep",
					args: []string{"exec", "test-pod", "--", "sleep", "2"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						// `kubectl exec` has sporadic warning message "Unknown stream id 1, discarding message", especially when
						// there are multiple concurrent streams so while `sleep` command has no output, `assert.Empty` would occasionally
						// fail. We'll assert the output doesn't contain the other `cat /etc/hostname` output instead.
						assert.NotContains(t, string(output), testutil.TestPodName)
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()

						expectedHeader := sessionrecorder.AsciicastHeader{
							Version:   2,
							Width:     0,
							Height:    0,
							Timestamp: 0,
							Command:   "sleep 2",
							User:      user.Username,
						}
						expectedEvents := []string{""}
						testutil.AssertLogsForExecOrAttach(
							t,
							logs,
							fmt.Sprintf("/api/v1/namespaces/default/pods/%s/exec?command=sleep&command=2&container=%s&stderr=true&stdout=true", testutil.TestPodName, testutil.TestPodName),
							expectedUser,
							expectedHeader,
							expectedEvents,
						)
					},
				},
				{
					name: "exec-cat",
					args: []string{"exec", testutil.TestPodName, "--", "cat", "/etc/hostname"},
					assertOutputFn: func(t *testing.T, output []byte) {
						t.Helper()
						// `kubectl exec` has sporadic warning message "Unknown stream id 1, discarding message", especially when
						// there are multiple concurrent streams so we can't `assert.Equal` here.
						assert.Contains(t, string(output), testutil.TestPodName)
					},
					assertLogFn: func(t *testing.T, logs *observer.ObservedLogs) {
						t.Helper()

						expectedHeader := sessionrecorder.AsciicastHeader{
							Version:   2,
							Width:     0,
							Height:    0,
							Timestamp: 0,
							Command:   "cat /etc/hostname",
							User:      user.Username,
						}
						expectedEvents := []string{"", testutil.TestPodName + "\n"}
						testutil.AssertLogsForExecOrAttach(
							t,
							logs,
							fmt.Sprintf("/api/v1/namespaces/default/pods/%s/exec?command=cat&command=%%2Fetc%%2Fhostname&container=%s&stderr=true&stdout=true", testutil.TestPodName, testutil.TestPodName),
							expectedUser,
							expectedHeader,
							expectedEvents,
						)
					},
				},
			}
			rand.Shuffle(len(commands), func(i, j int) {
				commands[i], commands[j] = commands[j], commands[i]
			})

			t.Logf("User %s is running commands: %s", user.ID, commands)

			for _, cmd := range commands {
				lastLogTime := time.Time{}

				output, err := user.Kubectl.Command(cmd.args...)
				if err != nil {
					t.Logf("Failed to run kubectl %s: %v", cmd.name, err)
				}

				cmd.assertOutputFn(t, output)

				// Wait for the logs to be flushed
				time.Sleep(100 * time.Millisecond)

				// Get user logs since last command
				userLogs := logs.Filter(func(e observer.LoggedEntry) bool {
					if !e.Time.After(lastLogTime) {
						return false
					}

					for _, ctxField := range e.Context {
						if ctxField.Equals(zap.Object("user", user.User)) {
							return true
						}
					}

					return false
				})
				cmd.assertLogFn(t, userLogs)
			}
		})
	}

	wg.Wait()
}

type command struct {
	name           string
	args           []string
	assertOutputFn func(t *testing.T, output []byte)
	assertLogFn    func(t *testing.T, logs *observer.ObservedLogs)
}

func (c command) String() string {
	return c.name
}
