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

// Package websockify implements a Caddy HTTP handler which proxies
// WebSocket connections to TCP or Unix sockets.
package websockify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coder/websocket"
	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// maxBufferSize is the largest allowed copy buffer size.
const maxBufferSize = 64 << 20 // MiB

// closeTimeout is how long [Module.Cleanup] waits for connections to close.
const closeTimeout = time.Second

func init() {
	caddy.RegisterModule(Module{})
	httpcaddyfile.RegisterHandlerDirective("websockify", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("websockify", httpcaddyfile.Before, "reverse_proxy")
}

var (
	_ caddyfile.Unmarshaler       = (*Module)(nil)
	_ caddy.Provisioner           = (*Module)(nil)
	_ caddy.Validator             = (*Module)(nil)
	_ caddy.CleanerUpper          = (*Module)(nil)
	_ caddyhttp.MiddlewareHandler = (*Module)(nil)
)

// Module proxies binary WebSocket connections to an upstream tcp or unix
// socket, passing non-WebSocket requests to the next handler.
//
// WebSocket requests using an HTTP/2 or HTTP/3 Extended CONNECT are supported
// in addition to HTTP/1.1 upgrades (but clients currently won't use it in
// practice).
type Module struct {
	// Upstream addresses in Caddy format, like "localhost:5900",
	// "tcp6/[::1]:5900", or "unix//run/vnc.sock". Placeholders are expanded for
	// each request. Multiple addresses are used round-robin across all
	// connections, trying each one once sequentially until one connects or all
	// fail.
	Upstreams []string `json:"upstreams,omitempty"`

	// Timeout for connecting to each upstream. If not specified, a default
	// timeout is used.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// TCP keepalive interval for the upstream connection, or negative to
	// disable it. If not specified, a default interval is used.
	KeepAlive caddy.Duration `json:"keepalive,omitempty"`

	// How often to send WebSocket pings to the downstream client, or negative
	// to disable it. If not specified, a default interval is used.
	PingInterval caddy.Duration `json:"ping_interval,omitempty"`

	// How long to wait for a pong from the downstream client before closing the
	// connection. Defaults to the ping interval. Time spent receiving data from
	// the client or waiting to write it to a slow upstream doesn't count.
	PingTimeout caddy.Duration `json:"ping_timeout,omitempty"`

	// Close the connection if no data is transferred in either direction for
	// this long, excluding pings. If not specified, the idle timeout is
	// disabled.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// Copy buffer size, for each direction, which is also the largest chunk
	// sent to the client in a single message at a time. If not specified, a
	// default size is used.
	BufferSize int `json:"buffer_size,omitempty"`

	// Allowed Origin header host patterns (path.Match syntax, or
	// "scheme://host" to match the scheme too) for cross-origin connections.
	// Same-origin connections and ones without an Origin header are always
	// allowed. Use "*" to allow any origin.
	Origins []string `json:"origins,omitempty"`

	// Subprotocols to negotiate. If not specified, "binary" is used.
	Subprotocols []string `json:"subprotocols,omitempty"`

	// Grace period to keep connections open after the config is unloaded (e.g.,
	// on reload). If not specified, they're closed immediately.
	StreamCloseDelay caddy.Duration `json:"stream_close_delay,omitempty"`

	logger    *zap.Logger
	dialer    net.Dialer
	cfg       Config
	anyOrigin bool
	next      *atomic.Uint64 // upstream round-robin counter
	active    *atomic.Int64  // number of open connections
	streams   *atomic.Int64  // number of open connections using an Extended CONNECT
	stopping  *atomic.Bool   // if the config has started being unloaded
	ctx       context.Context
	cancel    context.CancelFunc
}

func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.websockify",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	upstreams := func(args []string) error {
		for _, u := range args {
			if err := checkUpstream(u); err != nil {
				return d.Err(err.Error())
			}
		}
		m.Upstreams = append(m.Upstreams, args...)
		return nil
	}
	if err := upstreams(d.RemainingArgs()); err != nil {
		return err
	}

	for d.NextBlock(0) {
		var err error
		switch d.Val() {
		case "to":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			err = upstreams(args)
		case "dial_timeout":
			m.DialTimeout, err = parseDuration(d, false)
		case "keepalive":
			m.KeepAlive, err = parseDuration(d, true)
		case "ping_interval":
			m.PingInterval, err = parseDuration(d, true)
		case "ping_timeout":
			m.PingTimeout, err = parseDuration(d, false)
		case "idle_timeout":
			m.IdleTimeout, err = parseDuration(d, false)
		case "buffer_size":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.BufferSize, err = parseBufferSize(d.Val())
			if err != nil {
				return d.Err(err.Error())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		case "origins":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.Origins = append(m.Origins, args...)
		case "subprotocols":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.Subprotocols = append(m.Subprotocols, args...)
		case "stream_close_delay":
			m.StreamCloseDelay, err = parseDuration(d, false)
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
		if err != nil {
			return err
		}
	}
	if len(m.Upstreams) == 0 {
		return d.Err("no upstreams specified")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var w Module
	err := w.UnmarshalCaddyfile(h.Dispenser)
	return &w, err
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.DialTimeout == 0 {
		m.DialTimeout = caddy.Duration(10 * time.Second)
	}
	if m.PingInterval == 0 {
		m.PingInterval = caddy.Duration(30 * time.Second)
	}

	m.dialer = net.Dialer{
		Timeout:   time.Duration(m.DialTimeout),
		KeepAlive: time.Duration(m.KeepAlive),
	}
	m.cfg = Config{
		PingInterval: max(time.Duration(m.PingInterval), 0),
		PingTimeout:  time.Duration(m.PingTimeout),
		IdleTimeout:  time.Duration(m.IdleTimeout),
		BufferSize:   m.BufferSize,
	}
	for _, o := range m.Origins {
		if o == "*" {
			m.anyOrigin = true
		}
	}
	if len(m.Subprotocols) == 0 {
		m.Subprotocols = []string{"binary"}
	}

	m.next = new(atomic.Uint64)
	m.active = new(atomic.Int64)
	m.streams = new(atomic.Int64)
	m.stopping = new(atomic.Bool)

	// not derived from the caddy context since connections may outlive it
	m.ctx, m.cancel = context.WithCancel(context.Background())

	// HACK: close connections when the config starts being unloaded instead of
	// waiting for Cleanup if any are using an Extended CONNECT (a WebSocket
	// connection using an Extended CONNECT is technically an in-progress
	// request, so the server doesn't shut down until it ends, and if the
	// process is exiting, Cleanup isn't called until it has)
	events, err := ctx.App("events")
	if err != nil {
		return fmt.Errorf("getting events app: %v", err)
	}
	return events.(*caddyevents.App).On("stopping", eventHandlerFunc(func() {
		m.stopping.Store(true)
		if m.streams.Load() > 0 {
			m.stop()
		}
	}))
}

func (m *Module) Validate() error {
	if len(m.Upstreams) == 0 {
		return errors.New("no upstreams")
	}
	for _, u := range m.Upstreams {
		if err := checkUpstream(u); err != nil {
			return err
		}
	}
	if m.DialTimeout < 0 {
		return errors.New("dial_timeout must not be negative")
	}
	if m.PingTimeout < 0 {
		return errors.New("ping_timeout must not be negative")
	}
	if m.IdleTimeout < 0 {
		return errors.New("idle_timeout must not be negative")
	}
	if m.BufferSize < 0 {
		return errors.New("buffer_size must not be negative")
	}
	if m.BufferSize > maxBufferSize {
		return fmt.Errorf("buffer_size must not be larger than %s", humanize.IBytes(maxBufferSize))
	}
	for _, o := range m.Origins {
		if _, err := path.Match(strings.ToLower(o), ""); err != nil {
			return fmt.Errorf("origin pattern %q: %w", o, err)
		}
	}
	if m.StreamCloseDelay < 0 {
		return errors.New("stream_close_delay must not be negative")
	}
	return nil
}

// stop closes all connections, after the stream close delay if set.
func (m *Module) stop() {
	if m.StreamCloseDelay > 0 {
		time.AfterFunc(time.Duration(m.StreamCloseDelay), m.cancel)
	} else {
		m.cancel()
	}
}

func (m *Module) Cleanup() error {
	m.stop()
	if m.StreamCloseDelay > 0 {
		return nil
	}

	// give connections time to send their close frames, which are otherwise
	// lost if the process is exiting
	for start := time.Now(); m.active.Load() > 0 && time.Since(start) < closeTimeout; {
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func (m *Module) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	stream := isExtendedConnect(r)
	if stream {
		// [websocket.Accept] needs to hijack the connection, which isn't
		// possible for HTTP/2 and HTTP/3, so handle it like a HTTP/1.1 upgrade
		// of the stream. This is rarely used since clients only send an
		// Extended CONNECT if the server advertises support for it, which Go's
		// HTTP/2 server only does with GODEBUG=http2xconnect=1, so HTTP/2
		// clients use a separate HTTP/1.1 connection instead. quic-go always
		// advertises it for HTTP/3, but only clients implementing RFC 9220 use
		// it (and this is effectively nonexistent in practice, as WebTransport
		// ended up replacing it).
		w, r = extendedConnect(w, r)
	} else if !IsWebSocket(r) {
		return next.ServeHTTP(w, r)
	}

	// validate the handshake before dialing so invalid or cross-origin requests
	// can't cause connections to the upstream (Accept checks it again the same
	// way)
	if status, err := checkHandshake(w, r); err != nil {
		return caddyhttp.Error(status, err)
	}
	if !m.anyOrigin {
		if err := checkOrigin(r, m.Origins); err != nil {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// dial first so we can still respond with an error
	up, addr, err := m.dial(r.Context(), repl)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	m.active.Add(1)
	defer m.active.Add(-1)

	if stream {
		m.streams.Add(1)
		defer m.streams.Add(-1)

		// the stopping event handler didn't see this one
		if m.stopping.Load() {
			m.stop()
		}
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       m.Subprotocols,
		OriginPatterns:     m.Origins,
		InsecureSkipVerify: m.anyOrigin,
	})
	if err != nil {
		// Accept already wrote the response
		up.Close()
		m.logger.Debug("websocket handshake failed", zap.String("upstream", addr), zap.Error(err))
		return nil
	}

	start := time.Now()
	stats, err := Proxy(m.ctx, ws, up, m.cfg)
	lvl := zapcore.DebugLevel
	if err != nil {
		lvl = zapcore.InfoLevel
	}
	m.logger.Log(lvl, "connection closed",
		zap.String("upstream", addr),
		zap.Duration("duration", time.Since(start)),
		zap.Int64("bytes_up", stats.BytesUp),
		zap.Int64("bytes_down", stats.BytesDown),
		zap.Error(err),
	)
	return nil
}

// dial attempts to connect to each upstream in order.
func (m *Module) dial(ctx context.Context, repl *caddy.Replacer) (net.Conn, string, error) {
	var errs []error
	n := uint64(len(m.Upstreams))
	start := m.next.Add(1) - 1
	for i := range n {
		addr := repl.ReplaceAll(m.Upstreams[(start+i)%n], "")
		na, err := parseUpstream(addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		conn, err := m.dialer.DialContext(ctx, na.Network, na.JoinHostPort(0))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return conn, addr, nil
	}
	return nil, "", errors.Join(errs...)
}

// checkUpstream validates an upstream address, unless it contains placeholders.
func checkUpstream(addr string) error {
	if strings.Contains(addr, "{") {
		return nil
	}
	_, err := parseUpstream(addr)
	return err
}

// parseUpstream parses a caddy-style network address, only accepting known
// stream socket address types.
func parseUpstream(addr string) (caddy.NetworkAddress, error) {
	na, err := caddy.ParseNetworkAddress(addr)
	if err != nil {
		return na, fmt.Errorf("upstream %q: %w", addr, err)
	}
	switch na.Network {
	case "tcp", "tcp4", "tcp6", "unix":
	default:
		return na, fmt.Errorf("upstream %q: unsupported network %q", addr, na.Network)
	}
	if na.PortRangeSize() != 1 {
		return na, fmt.Errorf("upstream %q: port ranges are not supported", addr)
	}
	if !na.IsUnixNetwork() && na.StartPort == 0 {
		return na, fmt.Errorf("upstream %q: missing port", addr)
	}
	return na, nil
}

// parseDuration parses a single duration argument. If off is true, "off"
// becomes -1.
func parseDuration(d *caddyfile.Dispenser, off bool) (caddy.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	val := d.Val()
	if d.NextArg() {
		return 0, d.ArgErr()
	}
	v, err := parseDurationValue(val, off)
	if err != nil {
		return 0, d.Err(err.Error())
	}
	return v, nil
}

// parseDurationValue parses a duration. If off is true, "off" becomes -1.
func parseDurationValue(val string, off bool) (caddy.Duration, error) {
	if off && val == "off" {
		return -1, nil
	}
	v, err := caddy.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("bad duration %q: %v", val, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", val)
	}
	return caddy.Duration(v), nil
}

// parseBufferSize parses a copy buffer size.
func parseBufferSize(val string) (int, error) {
	size, err := humanize.ParseBytes(val)
	if err != nil {
		return 0, fmt.Errorf("bad buffer size %q: %v", val, err)
	}
	if size > maxBufferSize {
		return 0, fmt.Errorf("buffer size %q is too large", val)
	}
	return int(size), nil
}

type eventHandlerFunc func()

func (fn eventHandlerFunc) Handle(context.Context, caddy.Event) error {
	fn()
	return nil
}
