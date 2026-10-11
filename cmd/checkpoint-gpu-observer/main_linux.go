//go:build linux

package main

import (
	"log"

	"vram-governor/internal/checkpointgpuobserver"
)

func main() {
	if err := checkpointgpuobserver.RunFixedService(); err != nil {
		log.Fatal(err)
	}
}
