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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// note: this is mostly based on the built-in reverse-proxy command, and most
// flags are compatible (e.g., internal-certs, disable-redirects, insecure,
// change-host-header, header-up) (and I used the same usage text where
// possible for consistency)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "websockify",
		Usage: `[--from <addr>] [--to <addr>] [--origins <patterns>] [--basic-auth <username:password>] [--root <path>] [--browse] [--precompressed <encodings>] [--reverse-proxy <addr>] [--change-host-header] [--insecure] [--header-up "Field: value"] [--header-down "Field: value"] [--internal-certs] [--disable-redirects] [--access-log] [--debug]`,
		Short: "A quick and production-ready WebSocket to TCP proxy",
		Long: `
A simple but production-ready WebSocket to TCP proxy.

Proxies binary WebSocket connections received on the --from address to the
--to address, which is a TCP address like localhost:5900 or a Unix socket like
unix//run/vnc.sock. Multiple --to addresses may be specified by repeating the
flag.

Unless otherwise specified in the address, the --from address will be assumed
to be HTTPS if a hostname is given.

If the --from address has a host or IP, Caddy will attempt to serve the proxy
over HTTPS with a certificate (unless overridden by the HTTP scheme or port).

If serving HTTPS:
  --disable-redirects can be used to avoid binding to the HTTP port.
  --internal-certs can be used to force issuance certs using the internal
    CA instead of attempting to issue a public certificate.

For WebSocket connections:
  --origins allows cross-origin connections from hosts matching the patterns.
    Same-origin connections are always allowed. Use "*" to allow any origin.
  --subprotocols, --dial-timeout, --keepalive, --ping-interval,
    --ping-timeout, --idle-timeout, and --buffer-size are the same as the
    options of the websockify handler.

For authentication, which applies to all requests:
  --basic-auth requires HTTP basic authentication. It can be repeated to add
    more users. A password starting with "$" is treated as a bcrypt or
    argon2id hash from 'caddy hash-password'.

For serving static files (like caddy file-server):
  --root serves static files from a directory.
  --browse responds to requests for folders in --root without an index file
    with a file listing.
  --precompressed serves precompressed files in --root for the specified
    encodings (e.g., zstd,br,gzip) if they exist, preferring them in the order
    specified.

For proxying other requests to another backend (like caddy reverse-proxy):
  --reverse-proxy proxies requests to an HTTP upstream (or if --root is also
    specified, only requests not matching a file). Multiple addresses may be
    specified by repeating the flag. The address is assumed to be HTTP unless
    it has the HTTPS scheme.
  --header-up can be used to set a request header to send to the reverse
    proxy upstream.
  --change-host-header sets the Host header on the request to the address
    of the reverse proxy upstream, instead of defaulting to the incoming Host
    header.
  --insecure disables TLS verification with the reverse proxy upstream.
    WARNING: THIS DISABLES SECURITY BY NOT VERIFYING THE UPSTREAM'S
    CERTIFICATE.

For all responses:
  --header-down can be used to set a response header.

If a request is not a WebSocket connection, nor does it match a static file in
--root if specified, and --reverse-proxy is not specified either, a 404 will be
served.

Full documentation is available at:
https://github.com/pgaskin/caddy-websockify
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("from", "f", "localhost", "Address on which to receive traffic")                                                                       // matches reverse-proxy
			cmd.Flags().StringSliceP("to", "t", []string{}, "Upstream address(es) to which WebSocket connections should be proxied")                                   // websockify module (like reverse-proxy --to)
			cmd.Flags().StringSliceP("origins", "", []string{}, "Allowed host patterns for cross-origin WebSocket connections")                                        // websockify module
			cmd.Flags().StringSliceP("subprotocols", "", []string{}, "WebSocket subprotocols to negotiate (default binary)")                                           // websockify module
			cmd.Flags().StringP("dial-timeout", "", "", "Timeout for connecting to each upstream")                                                                     // websockify module
			cmd.Flags().StringP("keepalive", "", "", "TCP keepalive interval for the upstream connection, or \"off\"")                                                 // websockify module
			cmd.Flags().StringP("ping-interval", "", "", "How often to send WebSocket pings to the client, or \"off\"")                                                // websockify module
			cmd.Flags().StringP("ping-timeout", "", "", "How long to wait for a pong before closing the connection")                                                   // websockify module
			cmd.Flags().StringP("idle-timeout", "", "", "Close connections with no data transferred for this long")                                                    // websockify module
			cmd.Flags().StringP("buffer-size", "", "", "Copy buffer size for each direction")                                                                          // websockify module
			cmd.Flags().StringArrayP("basic-auth", "", []string{}, "Require HTTP basic authentication (format: \"username:password\")")                                // websockify command
			cmd.Flags().StringP("root", "", "", "Serve static files from this path")                                                                                   // matches file-server
			cmd.Flags().BoolP("browse", "b", false, "Enable directory browsing")                                                                                       // matches file-server
			cmd.Flags().StringSliceP("precompressed", "p", []string{}, "Specify precompression file extensions. Compression preference implied from flag order.")      // matches file-server
			cmd.Flags().StringSliceP("reverse-proxy", "", []string{}, "HTTP upstream address(es) to which other requests should be proxied")                           // reverse-proxy --to
			cmd.Flags().BoolP("change-host-header", "c", false, "Set reverse proxy upstream Host header to address of upstream")                                       // matches reverse-proxy
			cmd.Flags().BoolP("insecure", "", false, "Disable TLS verification for the reverse proxy (WARNING: DISABLES SECURITY BY NOT VERIFYING TLS CERTIFICATES!)") // matches reverse-proxy
			cmd.Flags().StringArrayP("header-up", "H", []string{}, "Set a request header to send to the reverse proxy upstream (format: \"Field: value\")")            // matches reverse-proxy
			cmd.Flags().StringArrayP("header-down", "d", []string{}, "Set a response header to send back to the client (format: \"Field: value\")")                    // matches reverse-proxy
			cmd.Flags().BoolP("disable-redirects", "r", false, "Disable HTTP->HTTPS redirects")                                                                        // matches reverse-proxy
			cmd.Flags().BoolP("internal-certs", "i", false, "Use internal CA for issuing certs")                                                                       // matches reverse-proxy
			cmd.Flags().BoolP("access-log", "", false, "Enable the access log")                                                                                        // matches reverse-proxy
			cmd.Flags().BoolP("debug", "v", false, "Enable verbose debug logs")                                                                                        // matches reverse-proxy
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdWebsockify)
		},
	})
}

func cmdWebsockify(fs caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	cfg, from, err := commandConfig(fs)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if err := caddy.Run(cfg); err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	to, _ := fs.GetStringSlice("to")
	caddy.Log().Info("caddy proxying websockets", zap.String("from", from), zap.Strings("to", to))

	select {}
}

func commandConfig(fs caddycmd.Flags) (*caddy.Config, string, error) {
	from := fs.String("from")
	changeHost := fs.Bool("change-host-header")
	insecure := fs.Bool("insecure")
	disableRedir := fs.Bool("disable-redirects")
	internalCerts := fs.Bool("internal-certs")
	accessLog := fs.Bool("access-log")
	debug := fs.Bool("debug")

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)

	fromAddr, err := httpcaddyfile.ParseAddress(from)
	if err != nil {
		return nil, "", fmt.Errorf("invalid downstream address %s: %v", from, err)
	}
	if fromAddr.Path != "" {
		return nil, "", fmt.Errorf("paths are not allowed: %s", from)
	}
	if fromAddr.Scheme == "" {
		if fromAddr.Port == httpPort || fromAddr.Host == "" {
			fromAddr.Scheme = "http"
		} else {
			fromAddr.Scheme = "https"
		}
	}
	if fromAddr.Port == "" {
		switch fromAddr.Scheme {
		case "http":
			fromAddr.Port = httpPort
		case "https":
			fromAddr.Port = httpsPort
		}
	}

	var handlers []json.RawMessage

	// set up header_down
	headerDown, err := parseHeaderFlag(fs, "header-down")
	if err != nil {
		return nil, "", err
	}
	if headerDown != nil {
		// set the headers immediately so error responses have them, and again
		// when the response is written to replace the ones set by the other
		// handlers
		for _, deferred := range []bool{false, true} {
			handlers = append(handlers, caddyconfig.JSONModuleObject(headers.Handler{
				Response: &headers.RespHeaderOps{
					HeaderOps: &headers.HeaderOps{Set: headerDown},
					Deferred:  deferred,
				},
			}, "handler", "headers", nil))
		}
	}

	// set up authentication
	auth, err := commandAuth(fs)
	if err != nil {
		return nil, "", err
	}
	if auth != nil {
		handlers = append(handlers, auth)
	}

	// set up the websocket handler
	ws := Module{}
	if ws.Upstreams, err = fs.GetStringSlice("to"); err != nil {
		return nil, "", fmt.Errorf("invalid to flag: %v", err)
	}
	if len(ws.Upstreams) == 0 {
		return nil, "", errors.New("--to is required")
	}
	if ws.Origins, err = fs.GetStringSlice("origins"); err != nil {
		return nil, "", fmt.Errorf("invalid origins flag: %v", err)
	}
	if ws.Subprotocols, err = fs.GetStringSlice("subprotocols"); err != nil {
		return nil, "", fmt.Errorf("invalid subprotocols flag: %v", err)
	}
	for _, f := range []struct {
		name string
		off  bool
		dst  *caddy.Duration
	}{
		{"dial-timeout", false, &ws.DialTimeout},
		{"keepalive", true, &ws.KeepAlive},
		{"ping-interval", true, &ws.PingInterval},
		{"ping-timeout", false, &ws.PingTimeout},
		{"idle-timeout", false, &ws.IdleTimeout},
	} {
		if val := fs.String(f.name); val != "" {
			if *f.dst, err = parseDurationValue(val, f.off); err != nil {
				return nil, "", fmt.Errorf("invalid %s flag: %v", f.name, err)
			}
		}
	}
	if val := fs.String("buffer-size"); val != "" {
		if ws.BufferSize, err = parseBufferSize(val); err != nil {
			return nil, "", fmt.Errorf("invalid buffer-size flag: %v", err)
		}
	}
	if err := ws.Validate(); err != nil {
		return nil, "", err
	}
	handlers = append(handlers, caddyconfig.JSONModuleObject(ws, "handler", "websockify", nil))

	// set up the other handlers
	proxy, err := commandReverseProxy(fs)
	if err != nil {
		return nil, "", err
	}
	static, err := commandFileServer(fs, proxy != nil)
	if err != nil {
		return nil, "", err
	}
	if static != nil {
		handlers = append(handlers, static)
	}
	if proxy != nil {
		handlers = append(handlers, proxy)
	} else {
		if changeHost || insecure || fs.Changed("header-up") {
			return nil, "", errors.New("--change-host-header, --insecure, and --header-up require --reverse-proxy")
		}
		if static == nil {
			handlers = append(handlers, caddyconfig.JSONModuleObject(caddyhttp.StaticError{
				StatusCode: caddyhttp.WeakString(strconv.Itoa(http.StatusNotFound)),
			}, "handler", "error", nil))
		}
	}

	route := caddyhttp.Route{HandlersRaw: handlers}
	if fromAddr.Host != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{fromAddr.Host}, nil),
			},
		}
	}

	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{route},
		Listen: []string{":" + fromAddr.Port},

		// like handle_errors
		Errors: &caddyhttp.HTTPErrorConfig{
			Routes: caddyhttp.RouteList{{
				HandlersRaw: []json.RawMessage{
					caddyconfig.JSONModuleObject(caddyhttp.StaticResponse{
						StatusCode: "{http.error.status_code}",
						Body:       "{http.error.status_code} {http.error.status_text}\n",
					}, "handler", "static_response", nil),
				},
			}},
		},
	}
	if accessLog {
		server.Logs = &caddyhttp.ServerLogConfig{}
	}

	if fromAddr.Scheme == "http" {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{Disabled: true}
	} else if disableRedir {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{DisableRedir: true}
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"websockify": server},
	}

	appsRaw := caddy.ModuleMap{
		"http": caddyconfig.JSON(httpApp, nil),
	}
	if internalCerts && fromAddr.Host != "" {
		tlsApp := caddytls.TLS{
			Automation: &caddytls.AutomationConfig{
				Policies: []*caddytls.AutomationPolicy{{
					SubjectsRaw: []string{fromAddr.Host},
					IssuersRaw:  []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
				}},
			},
		}
		appsRaw["tls"] = caddyconfig.JSON(tlsApp, nil)
	}

	persist := false
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &persist,
			},
		},
		AppsRaw: appsRaw,
	}

	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
			},
		}
	}

	return cfg, fromAddr.String(), nil
}

func commandAuth(fs caddycmd.Flags) (json.RawMessage, error) {
	basicAuth, err := stringArrayFlag(fs, "basic-auth")
	if err != nil {
		return nil, err
	}
	if len(basicAuth) == 0 {
		return nil, nil
	}

	basic := caddyauth.HTTPBasicAuth{HashCache: new(caddyauth.Cache)}
	var algorithm string
	for i, a := range basicAuth {
		username, password, found := strings.Cut(a, ":")
		if !found || username == "" || password == "" {
			return nil, fmt.Errorf("basic-auth %d: invalid format (expecting \"username:password\")", i)
		}

		alg := "bcrypt"
		switch {
		case strings.HasPrefix(password, "$argon2id$"):
			alg = "argon2id"
			if _, _, err := caddyauth.DecodeHash([]byte(password)); err != nil {
				return nil, fmt.Errorf("basic-auth %d: invalid argon2id hash: %v", i, err)
			}
		case strings.HasPrefix(password, "$"):
			if _, err := (caddyauth.BcryptHash{}).Compare([]byte(password), nil); err != nil {
				return nil, fmt.Errorf("basic-auth %d: invalid password hash (expecting bcrypt or argon2id): %v", i, err)
			}
		default: // plaintext
			hash, err := caddyauth.BcryptHash{}.Hash([]byte(password))
			if err != nil {
				return nil, fmt.Errorf("basic-auth %d: %v", i, err)
			}
			password = string(hash)
		}
		if i != 0 && alg != algorithm {
			return nil, errors.New("basic-auth: argon2id hashes can't be used with bcrypt hashes or plaintext passwords")
		}
		algorithm = alg

		basic.AccountList = append(basic.AccountList, caddyauth.Account{
			Username: username,
			Password: password,
		})
	}
	basic.HashRaw = caddyconfig.JSON(map[string]string{"algorithm": algorithm}, nil)
	return caddyconfig.JSONModuleObject(caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"http_basic": caddyconfig.JSON(basic, nil),
		},
	}, "handler", "authentication", nil), nil
}

// like caddy file-server
func commandFileServer(fs caddycmd.Flags, passThru bool) (json.RawMessage, error) {
	root := fs.String("root")
	browse := fs.Bool("browse")
	precompressed, err := fs.GetStringSlice("precompressed")
	if err != nil {
		return nil, fmt.Errorf("invalid precompressed flag: %v", err)
	}
	if root == "" {
		if browse || len(precompressed) != 0 {
			return nil, errors.New("--browse and --precompressed require --root")
		}
		return nil, nil
	}

	handler := fileserver.FileServer{
		Root:     root,
		PassThru: passThru,
	}
	for _, compression := range precompressed {
		modID := "http.precompressed." + compression
		mod, err := caddy.GetModule(modID)
		if err != nil {
			return nil, fmt.Errorf("getting module named '%s': %v", modID, err)
		}
		inst := mod.New()
		precompress, ok := inst.(encode.Precompressed)
		if !ok {
			return nil, fmt.Errorf("module %s is not a precompressor; is %T", modID, inst)
		}
		if handler.PrecompressedRaw == nil {
			handler.PrecompressedRaw = make(caddy.ModuleMap)
		}
		handler.PrecompressedRaw[compression] = caddyconfig.JSON(precompress, nil)
		handler.PrecompressedOrder = append(handler.PrecompressedOrder, compression)
	}
	if browse {
		handler.Browse = new(fileserver.Browse)
	}
	return caddyconfig.JSONModuleObject(handler, "handler", "file_server", nil), nil
}

func commandReverseProxy(fs caddycmd.Flags) (json.RawMessage, error) {
	to, err := fs.GetStringSlice("reverse-proxy")
	if err != nil {
		return nil, fmt.Errorf("invalid reverse-proxy flag: %v", err)
	}
	if len(to) == 0 {
		return nil, nil // not enabled
	}

	// mixing schemes isn't supported
	var handler reverseproxy.Handler
	var scheme string
	for i, addr := range to {
		s, dial, err := parseReverseProxyUpstream(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid reverse proxy upstream address %s: %v", addr, err)
		}
		if i != 0 && s != scheme {
			return nil, errors.New("reverse proxy upstream addresses must use the same scheme")
		}
		scheme = s
		handler.Upstreams = append(handler.Upstreams, &reverseproxy.Upstream{Dial: dial})
	}

	ht := reverseproxy.HTTPTransport{}
	if scheme == "https" {
		ht.TLS = new(reverseproxy.TLSConfig)
		if fs.Bool("insecure") {
			ht.TLS.InsecureSkipVerify = true
		}
	}
	handler.TransportRaw = caddyconfig.JSONModuleObject(ht, "protocol", "http", nil)

	// set up header_up
	headerUp, err := parseHeaderFlag(fs, "header-up")
	if err != nil {
		return nil, err
	}
	if fs.Bool("change-host-header") {
		if headerUp == nil {
			headerUp = http.Header{}
		}
		headerUp.Set("Host", "{http.reverse_proxy.upstream.hostport}")
	}
	if headerUp != nil {
		handler.Headers = &headers.Handler{
			Request: &headers.HeaderOps{Set: headerUp},
		}
	}

	return caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil), nil
}

// like caddy reverse-proxy
func parseReverseProxyUpstream(addr string) (scheme, dial string, err error) {
	if !strings.Contains(addr, "://") {
		network, host, port, err := caddy.SplitNetworkAddress(addr)
		if err != nil {
			return "", "", err
		}
		if port == "" && !caddy.IsUnixNetwork(network) {
			port = "80"
		}
		return "http", caddy.JoinNetworkAddress(network, host, port), nil
	}
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("only the scheme, host, and port are supported")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme, caddy.JoinNetworkAddress("", u.Hostname(), port), nil
}

// like caddy reverse-proxy
func parseHeaderFlag(fs caddycmd.Flags, name string) (http.Header, error) {
	vals, err := stringArrayFlag(fs, name)
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}
	hdr := make(http.Header)
	for i, h := range vals {
		key, val, found := strings.Cut(h, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !found || key == "" || val == "" {
			return nil, fmt.Errorf("%s %d: invalid format \"%s\" (expecting \"Field: value\")", name, i, h)
		}
		hdr.Set(key, val)
	}
	return hdr, nil
}

func stringArrayFlag(fs caddycmd.Flags, name string) ([]string, error) {
	vals, err := fs.GetStringArray(name)
	if err != nil {
		return nil, fmt.Errorf("invalid %s flag: %v", name, err)
	}
	if len(vals) == 0 && fs.Changed(name) {
		vals = []string{""} // single empty value (GetStringArray returns nothing)
	}
	return vals, nil
}
