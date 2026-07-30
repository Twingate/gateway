// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package data

import (
	_ "embed"
)

//go:embed client/key.pem
var ClientKey []byte

//go:embed controller/key.pem
var ControllerKey []byte

//go:embed proxy/tls.crt
var ProxyCert []byte

//go:embed proxy/tls.key
var ProxyKey []byte

//go:embed api_server/tls.crt
var ServerCert []byte

//go:embed api_server/tls.key
var ServerKey []byte

//go:embed ssh/ca/ca.pub
var SSHCAPublicKey []byte

//go:embed ssh/host/host.pub
var SSHHostPublicKey []byte
