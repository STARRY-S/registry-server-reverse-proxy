package main

import (
	"os"

	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/commands"
	"github.com/STARRY-S/registry-server-reverse-proxy/pkg/utils"
)

func main() {
	utils.SetupLogrus()
	commands.Execute(os.Args[1:])
}
