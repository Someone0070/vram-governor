package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vram-governor/internal/comfyharness"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8190", "HTTP listen address; use a TLS private reverse proxy for remote access")
	comfyURL := flag.String("comfy-url", "http://127.0.0.1:8188", "private ComfyUI base URL")
	stateDirectory := flag.String("state-dir", "/var/lib/vram-governor/comfy-harness", "durable harness state directory")
	tokenEnv := flag.String("token-env", "VRAM_COMFY_HARNESS_TOKEN", "environment variable containing the bearer token")
	flag.Parse()
	token := os.Getenv(*tokenEnv)
	if token == "" {
		log.Fatalf("required bearer token environment variable %s is unset", *tokenEnv)
	}
	server, err := comfyharness.New(comfyharness.Options{ComfyURL: *comfyURL, Authorization: "Bearer " + token, StateDirectory: *stateDirectory})
	if err != nil {
		return err
	}
	defer func() {
		if err := server.Close(); err != nil {
			log.Printf("release harness state ownership: %v", err)
		}
	}()
	httpServer := &http.Server{Addr: *listen, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 30 * time.Minute, IdleTimeout: 2 * time.Minute}
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan error, 1)
	go func() {
		<-shutdownCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownDone <- httpServer.Shutdown(ctx)
	}()
	fmt.Printf("managed Comfy harness listening on %s\n", *listen)
	err = httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	if shutdownCtx.Err() != nil {
		if err := <-shutdownDone; err != nil {
			return err
		}
	}
	return nil
}
