package main

import (
	"context"
	"fmt"
	"os"

	"github.com/vps-pilot/vps-pilot/core/internal/mcpserver"
	"github.com/vps-pilot/vps-pilot/core/internal/state"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fail("usage: vps-pilot <mcp|version>")
	}

	switch os.Args[1] {
	case "mcp":
		store, err := state.OpenDefault(context.Background())
		if err != nil {
			fail(err.Error())
		}
		defer store.Close()
		if err := mcpserver.Run(context.Background()); err != nil {
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
