package commands

import (
	"fmt"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/utils"
	"github.com/spf13/cobra"
)

type versionCmd struct {
	*baseCmd
}

func newVersionCmd() *versionCmd {
	cc := &versionCmd{}
	cc.baseCmd = newBaseCmd(&cobra.Command{
		Use:  "version",
		Long: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("checker version %s\n", utils.Version)
		},
	})

	return cc
}

func (cc *versionCmd) getCommand() *cobra.Command {
	return cc.cmd
}
