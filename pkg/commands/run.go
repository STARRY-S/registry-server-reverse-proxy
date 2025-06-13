package commands

import (
	"github.com/spf13/cobra"
)

type runCmd struct {
	*baseCmd
}

func newRunCmd() *runCmd {
	cc := &runCmd{}
	cc.baseCmd = newBaseCmd(&cobra.Command{
		Use:  "run",
		Long: "Run the proxy server",
		Run: func(cmd *cobra.Command, args []string) {
		},
	})

	return cc
}

func (cc *runCmd) getCommand() *cobra.Command {
	return cc.cmd
}
