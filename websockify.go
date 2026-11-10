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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http/httpguts"
)

// IsWebSocket returns true if r is a WebSocket upgrade request.
func IsWebSocket(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade") &&
		httpguts.HeaderValuesContainsToken(r.Header["Upgrade"], "websocket")
}

// checkHandshake returns an error and the response status if r (which should
// have already been checked with [IsWebSocket]), is not a valid handshake,
// using the same rules as [websocket.Accept] (which doesn't currently let us
// call verifyClientRequest separately). The origin is not checked.
func checkHandshake(w http.ResponseWriter, r *http.Request) (int, error) {
	if !r.ProtoAtLeast(1, 1) {
		return http.StatusUpgradeRequired, fmt.Errorf("unsupported protocol %q", r.Proto)
	}
	if v := r.Header.Get("Sec-WebSocket-Version"); v != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		return http.StatusBadRequest, fmt.Errorf("unsupported websocket version %q", v)
	}
	keys := r.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return http.StatusBadRequest, fmt.Errorf("expected one Sec-WebSocket-Key header, got %d", len(keys))
	}
	if key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keys[0])); err != nil || len(key) != 16 {
		return http.StatusBadRequest, fmt.Errorf("invalid Sec-WebSocket-Key %q", keys[0])
	}
	return 0, nil
}

// checkOrigin returns an error if the Origin header of r is not allowed, using
// the same rules as [websocket.AcceptOptions.OriginPatterns] (since
// [websocket.Accept] doesn't currently let us call verifyClientRequest
// separately).
func checkOrigin(r *http.Request, patterns []string) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %w", origin, err)
	}
	if strings.EqualFold(r.Host, u.Host) {
		return nil
	}
	for _, pattern := range patterns {
		target := u.Host
		if strings.Contains(pattern, "://") {
			target = u.Scheme + "://" + u.Host
		}
		if ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(target)); ok {
			return nil
		}
	}
	return fmt.Errorf("origin %q is not allowed for host %q", origin, r.Host)
}

var (
	ErrIdleTimeout = errors.New("idle timeout")
	ErrPingTimeout = errors.New("ping timeout")
)

// Config controls [Proxy].
type Config struct {
	// PingInterval is the frequency to ping the client at, or zero to disable.
	PingInterval time.Duration

	// PingTimeout is how long to wait for a pong from the client. If zero,
	// [Config.PingInterval] is used. A ping only times out if nothing was
	// received from the client and no data was waiting to be written to the
	// upstream for the entire duration (since the pong may otherwise be queued
	// behind unread data).
	PingTimeout time.Duration

	// IdleTimeout closes the connection if no data is transferred in either
	// direction for this long, excluding pings, or zero to disable.
	IdleTimeout time.Duration

	// BufferSize is the copy buffer size for each direction, which is also the
	// largest chunk sent to the client in a single message at a time. If zero,
	// a reasonable default is used.
	BufferSize int
}

// Stats contains the number of bytes transferred in each direction.
type Stats struct {
	BytesUp   int64 // to server
	BytesDown int64 // to client
}

// Proxy copies binary messages to and from ws and upstream until either side
// closes, ctx is cancelled, the client stops responding to pings within the
// ping timeout (if pings are enabled), or no data is transferred and the idle
// timeout is reached.
//
// Both connections are closed before returning. Errors from Close on ws and
// upstream are ignored.
//
// The returned error is nil if either side ended the connection normally,
// otherwise [ErrIdleTimeout], [ErrPingTimeout], [context.Cause], or the error
// which caused the connection to end.
func Proxy(ctx context.Context, ws *websocket.Conn, upstream net.Conn, cfg Config) (Stats, error) {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 32 << 10 // KiB
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = cfg.PingInterval
	}

	ioctx, iocancel := context.WithCancel(context.Background())
	defer iocancel()

	b := &conn{
		cfg:   cfg,
		ws:    ws,
		nc:    websocket.NetConn(ioctx, ws, websocket.MessageBinary),
		up:    upstream,
		start: time.Now(),
		done:  make(chan struct{}),
	}
	b.waiting.Store(-1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.copyUp()
	}()
	go func() {
		defer wg.Done()
		b.copyDown()
	}()
	if cfg.PingInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.ping()
		}()
	}

	b.wait(ctx)

	_ = b.up.Close()
	if b.code == 0 {
		_ = b.ws.CloseNow()
	} else {
		_ = b.ws.Close(b.code, b.reason)
	}
	iocancel()
	wg.Wait()

	return Stats{
		BytesUp:   b.toUpstream.Load(),
		BytesDown: b.toClient.Load(),
	}, b.err
}

type conn struct {
	cfg Config
	ws  *websocket.Conn
	nc  net.Conn
	up  net.Conn

	start   time.Time
	active  atomic.Int64 // since start
	waiting atomic.Int64 // when copyUp started waiting for the client since start, or -1

	toUpstream atomic.Int64
	toClient   atomic.Int64

	once sync.Once
	done chan struct{}

	// set once done is closed
	err    error
	code   websocket.StatusCode // if zero, close without a handshake
	reason string
}

func (c *conn) stop(err error, code websocket.StatusCode, reason string) {
	c.once.Do(func() {
		c.err, c.code, c.reason = err, code, reason
		close(c.done)
	})
}

func (c *conn) wait(ctx context.Context) {
	var idle <-chan time.Time
	var timer *time.Timer
	if c.cfg.IdleTimeout > 0 {
		timer = time.NewTimer(c.cfg.IdleTimeout)
		defer timer.Stop()
		idle = timer.C
	}
	for {
		select {
		case <-c.done:
			return
		case <-ctx.Done():
			c.stop(context.Cause(ctx), websocket.StatusGoingAway, "server shutting down")
			return
		case <-idle:
			if d := c.cfg.IdleTimeout - c.idle(); d > 0 {
				timer.Reset(d)
				continue
			}
			c.stop(ErrIdleTimeout, websocket.StatusGoingAway, "idle timeout")
			return
		}
	}
}

func (c *conn) copyUp() {
	rerr, werr := c.copy(c.up, clientReader{c}, &c.toUpstream)
	switch {
	case werr != nil:
		c.stop(fmt.Errorf("write to upstream server: %w", werr), websocket.StatusBadGateway, "upstream error")
	case rerr == io.EOF, websocket.CloseStatus(rerr) != -1:
		c.stop(nil, 0, "")
	default:
		c.stop(fmt.Errorf("read from downstream client: %w", rerr), 0, "")
	}
}

func (c *conn) copyDown() {
	rerr, werr := c.copy(c.nc, c.up, &c.toClient)
	switch {
	case werr != nil:
		c.stop(fmt.Errorf("write to downstream client: %w", werr), 0, "")
	case rerr == io.EOF:
		c.stop(nil, websocket.StatusNormalClosure, "")
	default:
		c.stop(fmt.Errorf("read from upstream server: %w", rerr), websocket.StatusBadGateway, "upstream error")
	}
}

func (c *conn) copy(dst io.Writer, src io.Reader, n *atomic.Int64) (rerr, werr error) {
	buf := make([]byte, c.cfg.BufferSize)
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			c.active.Store(int64(time.Since(c.start)))
			nw, err := dst.Write(buf[:nr])
			n.Add(int64(nw))
			if err != nil {
				return nil, err
			}
			if nw != nr {
				return nil, io.ErrShortWrite
			}
		}
		if err != nil {
			return err, nil
		}
	}
}

// clientReader reads from the client, setting conn.waiting for the duration of
// each read.
type clientReader struct{ c *conn }

func (r clientReader) Read(p []byte) (int, error) {
	r.c.waiting.Store(int64(time.Since(r.c.start)))
	defer r.c.waiting.Store(-1)
	return r.c.nc.Read(p)
}

func (c *conn) ping() {
	t := time.NewTicker(c.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		sent := time.Since(c.start)
		// The context isn't cancelled when stopping since that would close the
		// connection without a close frame if the ping is still being written.
		// Closing the connection ends the ping.
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.PingTimeout)
		err := c.ws.Ping(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Pongs are only read while copyUp is waiting for the client.
				// If it wasn't for the entire timeout, data was received from
				// the client, or the pong may be queued behind data blocked on
				// the upstream.
				if w := time.Duration(c.waiting.Load()); w < 0 || w > sent {
					continue
				}
				err = ErrPingTimeout
			} else {
				err = fmt.Errorf("ping downstream client: %w", err)
			}
			c.stop(err, 0, "")
			return
		}
	}
}

func (c *conn) idle() time.Duration {
	return time.Since(c.start) - time.Duration(c.active.Load())
}
