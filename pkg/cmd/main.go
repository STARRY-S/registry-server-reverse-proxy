package main

import (
	"os"

	"github.com/STARRY-S/overlayer/pkg/commands"
	"github.com/STARRY-S/overlayer/pkg/utils"
)

func main() {
	utils.SetupLogrus()
	commands.Execute(os.Args[1:])
}
