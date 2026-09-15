// Copyright 2026
// SPDX-License-Identifier: MPL-2.0

//go:debug cryptocustomrand=1

// The injector needs the Vault Agent command, not the Vault server or the
// general-purpose Vault CLI. Keeping the command dispatch here deliberately
// small makes every non-Agent subcommand fail closed.
package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/vault/command"
	"github.com/hashicorp/vault/version"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "version", "-v", "-version", "--version":
			fmt.Fprintln(os.Stdout, version.GetVersion().FullVersionNumber(true))
			return
		}
	}

	if len(os.Args) < 2 || os.Args[1] != "agent" {
		fmt.Fprintln(os.Stderr, "this image supports only: vault agent [options]")
		os.Exit(64)
	}

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}
	agent := &command.AgentCommand{
		BaseCommand: &command.BaseCommand{UI: ui},
		ShutdownCh:  command.MakeShutdownCh(),
		SighupCh:    command.MakeSighupCh(),
		SigUSR2Ch:   command.MakeSigUSR2Ch(),
	}
	if len(os.Args) == 3 && (os.Args[2] == "-h" || os.Args[2] == "-help" || os.Args[2] == "--help") {
		fmt.Fprintln(os.Stdout, agent.Help())
		return
	}
	os.Exit(agent.Run(os.Args[2:]))
}
