package commands

import (
	"fmt"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/config"
	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type runOpts struct {
	ConfigFile string
}

type runCmd struct {
	*baseCmd
	*runOpts

	server server.Server
	config *config.Config
}

func newRunCmd() *runCmd {
	cc := &runCmd{
		runOpts: &runOpts{},
	}
	cc.baseCmd = newBaseCmd(&cobra.Command{
		Use:  "run",
		Long: "Run the proxy server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if cc.debug {
				logrus.SetLevel(logrus.DebugLevel)
				logrus.Debugf("Debug mode enabled")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cc.init(); err != nil {
				return fmt.Errorf("failed to initialize run command: %w", err)
			}
			return cc.run()
		},
	})
	flags := cc.cmd.Flags()
	flags.StringVarP(&cc.ConfigFile, "config", "c", "config.yaml", "Config file")

	return cc
}

func (cc *runCmd) init() error {
	if cc.ConfigFile == "" {
		return fmt.Errorf("config file not provided")
	}
	c, err := config.NewConfigFromFile(cc.ConfigFile)
	if err != nil {
		return err
	}
	cc.config = c

	s, err := server.NewRegistryServer(signalContext, cc.config)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}
	cc.server = s
	return nil
}

func (cc *runCmd) run() error {
	var err error
	if cc.config.Cert != "" {
		err = cc.server.ListenTLS(signalContext)
	} else {
		err = cc.server.Listen(signalContext)
	}
	return err
}

func (cc *runCmd) getCommand() *cobra.Command {
	return cc.cmd
}
