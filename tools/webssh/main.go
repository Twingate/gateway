// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js && wasm

// Command webssh is an SSH client that runs in a browser. It reaches the Gateway over a
// WebSocket, because a browser can neither open a raw TCP socket nor produce the
// Proof-of-Possession signature the Gateway's CONNECT handshake requires. The Twingate Client
// terminates the WebSocket and supplies both.
package main

import (
	"context"
	"io"
	"strings"
	"syscall/js"

	"golang.org/x/crypto/ssh"

	"github.com/coder/websocket"
)

const readBufferSize = 32 * 1024

func main() {
	js.Global().Set("twingateOpen", js.FuncOf(open))

	select {}
}

// open starts a shell session and wires it to the page. It takes the WebSocket URL, the SSH
// username and the terminal size, and returns immediately: the session runs on its own
// goroutine so the browser's event loop stays responsive.
func open(_ js.Value, args []js.Value) any {
	url := args[0].String()
	username := args[1].String()
	cols := args[2].Int()
	rows := args[3].Int()

	go func() {
		if err := runShell(url, username, cols, rows); err != nil {
			js.Global().Call("twingateOnClose", err.Error())

			return
		}

		js.Global().Call("twingateOnClose", "session ended")
	}()

	return nil
}

func runShell(url, username string, cols, rows int) error {
	ctx := context.Background()

	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return err
	}

	defer ws.CloseNow()

	// The Gateway presents a host certificate signed by the gateway host CA. A browser has no
	// known_hosts to check it against, so this POC accepts it unverified; pinning the CA public
	// key is what makes this safe in production.
	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // POC: see comment above
		// Without a callback the banner is discarded, so the Gateway's welcome message would
		// never reach the terminal. It arrives before the PTY exists, hence the CRLF fixup.
		BannerCallback: func(message string) error {
			writeTerminal([]byte(strings.ReplaceAll(strings.ReplaceAll(message, "\r\n", "\n"), "\n", "\r\n")))

			return nil
		},
	}

	// No auth method is configured: the Gateway accepts "none" because Twingate already
	// authenticated the tunnel.
	sshConn, channels, requests, err := ssh.NewClientConn(websocket.NetConn(ctx, ws, websocket.MessageBinary), url, config)
	if err != nil {
		return err
	}

	client := ssh.NewClient(sshConn, channels, requests)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}

	// A PTY merges stderr into stdout, so the single pipe carries everything the terminal shows.
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	if err := session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		return err
	}

	if err := session.Shell(); err != nil {
		return err
	}

	js.Global().Set("twingateSend", js.FuncOf(func(_ js.Value, args []js.Value) any {
		data := make([]byte, args[0].Get("length").Int())
		js.CopyBytesToGo(data, args[0])
		_, _ = stdin.Write(data)

		return nil
	}))

	js.Global().Set("twingateResize", js.FuncOf(func(_ js.Value, args []js.Value) any {
		_ = session.WindowChange(args[1].Int(), args[0].Int())

		return nil
	}))

	return pumpOutput(stdout)
}

func pumpOutput(stdout io.Reader) error {
	buffer := make([]byte, readBufferSize)

	for {
		n, err := stdout.Read(buffer)
		if n > 0 {
			writeTerminal(buffer[:n])
		}

		if err != nil {
			if err == io.EOF { //nolint:errorlint // io.Reader contract returns io.EOF unwrapped
				return nil
			}

			return err
		}
	}
}

// writeTerminal hands bytes to the page as a Uint8Array so that xterm.js does the UTF-8 decoding.
// Decoding in Go would corrupt runes split across reads.
func writeTerminal(b []byte) {
	chunk := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(chunk, b)
	js.Global().Call("twingateOnData", chunk)
}
