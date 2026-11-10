package websockify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

var (
	ErrIdleTimeout = errors.New("idle timeout")
	ErrPingTimeout = errors.New("ping timeout")
)

// Config controls Run.
type Config struct {
	// PingInterval is the frequency to ping the client at, or zero to disable.
	PingInterval time.Duration

	// PingTimeout is how long to wait for a pong from the client. If zero,
	// [Config.PingInterval] is used.
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
		cfg.BufferSize = 32 << 10 // kB
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = cfg.PingInterval
	}

	ioctx, iocancel := context.WithCancel(context.Background())
	defer iocancel()

	stopctx, stopcancel := context.WithCancel(context.Background())
	defer stopcancel()

	b := &conn{
		cfg:     cfg,
		ws:      ws,
		nc:      websocket.NetConn(ioctx, ws, websocket.MessageBinary),
		up:      upstream,
		start:   time.Now(),
		done:    make(chan struct{}),
		stopctx: stopctx,
		stopped: stopcancel,
	}

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

	start  time.Time
	active atomic.Int64 // since start

	toUpstream atomic.Int64
	toClient   atomic.Int64

	once    sync.Once
	done    chan struct{}
	stopctx context.Context
	stopped context.CancelFunc

	// set once done is closed
	err    error
	code   websocket.StatusCode // if zero, close without a handshake
	reason string
}

func (c *conn) stop(err error, code websocket.StatusCode, reason string) {
	c.once.Do(func() {
		c.err, c.code, c.reason = err, code, reason
		c.stopped()
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
	rerr, werr := c.copy(c.up, c.nc, &c.toUpstream)
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

func (c *conn) ping() {
	t := time.NewTicker(c.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(c.stopctx, c.cfg.PingTimeout)
		err := c.ws.Ping(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
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
