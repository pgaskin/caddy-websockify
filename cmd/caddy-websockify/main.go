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
