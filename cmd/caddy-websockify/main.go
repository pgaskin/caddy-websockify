// Command caddy-websockify is a Caddy build which runs the websockify command
// directly.
package main

import (
	"os"

	_ "time/tzdata"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/pgaskin/caddy-websockify"
)

func main() {
	c := caddycmd.Commands()["websockify"]
	cmd := &cobra.Command{
		Use:          "caddy-websockify " + c.Usage,
		Short:        c.Short,
		Long:         c.Long,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	c.CobraFunc(cmd)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
