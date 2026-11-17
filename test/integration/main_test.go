// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"fmt"
	"os"
	"testing"

	"gateway/test/fake"
)

const network = "acme"
const host = "test"

var controllerURL string

func TestMain(m *testing.M) {
	// Caddy reverse proxies acme.test, the JWKS host for network and host, to port 8080, so all
	// tests share one Controller.
	controller := fake.NewController(network, 8080)
	if controller == nil {
		fmt.Fprintln(os.Stderr, "failed to start Controller")
		os.Exit(1)
	}

	controllerURL = controller.URL

	m.Run()
	controller.Close()
}
