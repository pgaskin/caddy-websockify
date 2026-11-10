// Copyright 2026 Patrick Gaskin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package websockify

import (
	"bufio"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// streamWriteTimeout is how long a write in progress has to complete after a
// streamConn is closed.
const streamWriteTimeout = time.Second

// isExtendedConnect returns true if r is a WebSocket request using an HTTP/2
// (RFC 8441) or HTTP/3 (RFC 9220) Extended CONNECT instead of an upgrade.
func isExtendedConnect(r *http.Request) bool {
	if r.Method != http.MethodConnect {
		return false
	}
	switch r.ProtoMajor {
	case 2:
		return r.Header.Get(":protocol") == "websocket"
	case 3:
		// quic-go sets Proto to the :protocol pseudo-header
		return r.Proto == "websocket"
	}
	return false
}

// extendedConnect converts an Extended CONNECT WebSocket request into the
// equivalent HTTP/1.1 upgrade request, and wraps w so the stream can be
// hijacked like a HTTP/1.1 connection, since [websocket.Accept] only supports
// those. This is kind of hacky, but it works well enough.
func extendedConnect(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request) {
	u := r.Clone(r.Context())
	u.Method = http.MethodGet
	u.Proto, u.ProtoMajor, u.ProtoMinor = "HTTP/1.1", 1, 1
	u.Header.Del(":protocol")
	u.Header.Set("Connection", "Upgrade")
	u.Header.Set("Upgrade", "websocket")

	// An Extended CONNECT doesn't have a key. The value doesn't matter since
	// the Sec-WebSocket-Accept header is removed from the response.
	u.Header.Set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")

	return &streamResponseWriter{ResponseWriter: w, r: r}, u
}

// streamResponseWriter responds to an Extended CONNECT WebSocket request as if
// it was a HTTP/1.1 upgrade request.
type streamResponseWriter struct {
	http.ResponseWriter
	r *http.Request
}

func (w *streamResponseWriter) WriteHeader(status int) {
	if status == http.StatusSwitchingProtocols {
		// an Extended CONNECT is accepted with a 200 instead of an upgrade
		h := w.Header()
		h.Del("Connection")
		h.Del("Upgrade")
		h.Del("Sec-WebSocket-Accept")
		status = http.StatusOK
	}
	w.ResponseWriter.WriteHeader(status)
}

// Hijack returns the stream. Unlike a hijacked HTTP/1.1 connection, the stream
// ends when the handler returns.
func (w *streamResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rc := http.NewResponseController(w.ResponseWriter)
	if err := rc.Flush(); err != nil {
		return nil, nil, err
	}

	// the server's timeouts don't apply to hijacked connections
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	c := &streamConn{w: w.ResponseWriter, rc: rc, r: w.r}
	return c, bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c)), nil
}

// streamConn is the request and response body of an Extended CONNECT request.
type streamConn struct {
	w  http.ResponseWriter
	rc *http.ResponseController
	r  *http.Request

	mu     sync.Mutex
	closed bool
}

func (c *streamConn) Read(p []byte) (int, error) {
	return c.r.Body.Read(p)
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, c.rc.Flush()
}

// Close fails pending reads and new writes. The stream itself is closed when
// the handler returns.
func (c *streamConn) Close() error {
	c.mu.Lock()
	closed := c.closed
	c.closed = true
	c.mu.Unlock()
	if closed {
		return nil
	}

	// HACK: give in-progress writes time to complete instead of failing them
	// immediately, since failing it resets a HTTP/2 stream, and the client
	// might not have received the close frame yet
	_ = c.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))

	return c.r.Body.Close()
}

func (c *streamConn) LocalAddr() net.Addr {
	addr, _ := c.r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return addr
}

func (c *streamConn) RemoteAddr() net.Addr {
	addr, _ := netip.ParseAddrPort(c.r.RemoteAddr)
	if c.r.ProtoMajor == 3 {
		return net.UDPAddrFromAddrPort(addr)
	}
	return net.TCPAddrFromAddrPort(addr)
}

func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.rc.SetReadDeadline(t); err != nil {
		return err
	}
	return c.rc.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.rc.SetReadDeadline(t)
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.rc.SetWriteDeadline(t)
}
