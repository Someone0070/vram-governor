//go:build !linux

package main

import (
	"context"
	"log"

	"vram-governor/internal/nodeagent"
)

func main() {
	if err := nodeagent.RunCheckpointLocalObserver(context.Background()); err != nil {
		log.Fatal(err)
	}
}
