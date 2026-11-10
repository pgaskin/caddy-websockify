# caddy-websockify

Caddy plugin which proxies WebSocket connections to TCP or Unix sockets, like [websockify](https://github.com/novnc/websockify).

- Proxies binary WebSocket messages to and from a TCP or Unix socket upstream, with optional TLS (compatible with [`novnc/websockify`](https://github.com/novnc/websockify)).
- Works with other Caddy features (including fallthrough for non-websocket requests, handle_errors for websocket error responses, and dynamic placeholders in the upstream addresses).
- Supports multiple upstreams (round-robin with failover).
- Connects to the upstream before accepting the websocket.
- Supports WebSocket over HTTP/1.1, HTTP/2, and HTTP/3.
- Supports TCP keepalive and client pings.
- Supports graceful shutdown.
- Configurable timeouts and buffering.
- Configurable Origin header restrictions.

### Usage

#### Caddy

Build Caddy with the plugin using [xcaddy](https://github.com/caddyserver/xcaddy), or `import _ "github.com/pgaskin/caddy-websockify"`.

```bash
xcaddy build --with github.com/pgaskin/caddy-websockify
```

Then use the `websockify` directive, which is ordered before `reverse_proxy`. WebSocket requests are proxied to the configured upstream, and all other requests are passed to the next handler.


```caddyfile
websockify [<matcher>] [<upstreams...>] {
	to                 <upstreams...>
	dial_timeout       <duration>
	keepalive          off|<duration>
	ping_interval      off|<duration>
	ping_timeout       <duration>
	idle_timeout       <duration>
	buffer_size        <size>
	origins            <patterns...>
	subprotocols       <names...>
	stream_close_delay <duration>

	tls
	tls_server_name          <name>
	tls_insecure_skip_verify
	tls_trust_pool           <module> ...
	tls_client_auth          <automate_name> | <cert_file> <key_file>
	tls_timeout              <duration>
	tls_except_ports         <ports...>
	tls_curves               <curves...>
	tls_renegotiation        <level>
}
```

- **upstreams**, **to** are the addresses to connect to, like `localhost:5900`, `tcp6/[::1]:5900`, or `unix//run/vnc.sock` (placeholders are supported) (if there is more than one, they are used in round-robin, trying each one sequentially on failure).
- **dial_timeout** is the timeout for connecting to each upstream (if not specified, a default timeout is used).
- **keepalive** is the TCP keepalive interval for the upstream connection, or `off` to disable it (if not specified, a default interval is used).
- **ping_interval** is how often to send a WebSocket ping to the client, or `off` to disable it (if not specified, a default interval is used).
- **ping_timeout** is how long to wait for the pong before closing the connection (if not specified, this matches `ping_interval`).
- **idle_timeout** closes the connection if no data is transferred in either direction for the specified duration, excluding pings (if not specified, the idle timeout is disabled).
- **buffer_size** is the size of the copy buffer for each direction, which is also the largest message sent to the client (if not specified, a default size is used).
- **origins** are the allowed `Origin` hosts for cross-origin connections, as glob patterns like `*.example.com`, or `https://*.example.com` to match the scheme too, or `*` to allow any origin (same-origin connections and requests without an `Origin` header are always allowed).
- **subprotocols** are the WebSocket subprotocols to negotiate (if not specified, `binary` is used).
- **stream_close_delay** is the grace period to keep connections open after the config is unloaded (for example, on a reload) instead of closing them immediately.
- **tls**, **tls_\*** matches the built-in [`reverse_proxy` HTTP transport](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport), and uses TLS for the upstream connection if any are set.
- **tls_server_name** is set to the host of the upstream address by default, and must be configured explicitly for unix sockets and addresses without a host unless `tls_insecure_skip_verify` is set (placeholders are supported).
- **tls_timeout** is set to `dial_timeout` if not specified.

For example, to serve noVNC:

```caddyfile
vnc.example.com {
	websockify /websockify localhost:5900
	root * /usr/share/novnc
	file_server
	handle_errors {
		respond "{err.status_code} {err.status_text}"
	}
}
```

For WebSocket over HTTP/2, Caddy must currently be started with `GODEBUG=http2xconnect=1` in the environment. If not set, clients will use HTTP/1.1 for websocket connections.

#### Standalone

You can run `caddy-websockify` directly as a standalone binary instead of using a Caddyfile. It is also available as `caddy websockify` in a Caddy build with the plugin enabled.

```bash
# install
go install github.com/pgaskin/caddy-websockify/cmd/caddy-websockify@latest

# proxy WebSocket connections on port 6080 to a VNC server
caddy-websockify --from :6080 --to localhost:5900

# also serve noVNC from the same port
caddy-websockify --from :6080 --to localhost:5900 --root /usr/share/novnc

# serve over HTTPS (with HTTP/2 support) with an automatically issued
# certificate, require a password, and proxy to a Unix socket
GODEBUG=http2xconnect=1 caddy-websockify --from vnc.example.com --to unix//run/vnc.sock --root /usr/share/novnc --basic-auth 'user:password'

# serve over HTTPS (with HTTP/2 support) on localhost with a certificate
# from Caddy's internal CA, and proxy other requests to a web app
GODEBUG=http2xconnect=1 caddy-websockify --from https://localhost:6443 --internal-certs --to localhost:5900 --reverse-proxy localhost:8080

# proxy to an upstream using TLS
caddy-websockify --from :6080 --to vnc.example.com:5900 --tls

# show all options
caddy-websockify --help
```

### Comparison

| | [pgaskin/caddy-websockify](https://github.com/pgaskin/caddy-websockify) | [hadi77ir/caddy-websockify](https://github.com/hadi77ir/caddy-websockify/tree/f86fade08d5a9d9918d72d8930f0072ea2aaa803) | [msquee/go-websockify](https://github.com/msquee/go-websockify/tree/5d6773ee3ed8d5115262bdf82562dcab4c80c467) | [novnc/websockify](https://github.com/novnc/websockify/tree/1e284ea2c825377ec09b40164b64f6e0778e31fc) |
| --- | --- | --- | --- | --- |
| Language | Go | Go | Go | Python |
| Upstream types | TCP, Unix | TCP, WebSocket | TCP | TCP, Unix |
| Upstream TLS support | Yes | Yes | - | Yes |
| Multiple upstreams | Round-robin with failover | Round-robin | - | - |
| Dynamic upstreams | Caddyfile placeholders | - | - | Plugins |
| Upstream TCP keepalive | Configurable | Configurable | Go default | System default |
| Client pings | Optional, with a timeout | - | - | Optional, without a timeout |
| Idle timeout | Optional | - | - | - |
| WebSocket over HTTP/2 and HTTP/3 | Yes (if `GODEBUG=http2xconnect=1`) | - | - | - |
| Connects to the upstream before accepting the WebSocket | Yes (502 on failure) | - | - | - |
| Sends close frame on shutdown | Yes | - | - | - |
| Origin check | Optional | - | - | Optional, exact match only |
| Handshake subprotocols | Configurable | Not negotiated | `binary` | `binary` |
| CLI | Yes | Yes | Yes | Yes |
| CLI: HTTPS | Automatic (Caddy) | Automatic (Caddy) | - | Manual |
| CLI: Static files | Yes | - | - | Yes |
| CLI: Authentication | Optional (basic, or Caddyfile) | - | - | Optional (basic, client certificate) |
