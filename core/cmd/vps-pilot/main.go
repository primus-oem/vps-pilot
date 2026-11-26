package main

import (
	"context"
	"fmt"
	"os"

	"github.com/primus-oem/vps-pilot/core/internal/mcpserver"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fail("usage: vps-pilot <mcp|host|app|secret|version>")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "app":
		if err := runAppCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "secret":
		if err := runSecretCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "host":
		if err := runHostCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "mcp":
		store, err := state.OpenDefault(ctx)
		if err != nil {
			fail(err.Error())
		}
		defer store.Close()
		if err := mcpserver.Run(ctx, version, store); err != nil {
			fail(err.Error())
		}
	case "version":
		fmt.Println(version)
	default:
		fail("unknown command")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
