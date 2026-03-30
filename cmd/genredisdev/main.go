package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alicebob/miniredis/v2"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:16379", "listen address for embedded dev redis")
	flag.Parse()

	server := miniredis.NewMiniRedis()
	if err := server.StartAddr(*listen); err != nil {
		log.Fatalf("start embedded redis: %v", err)
	}
	defer server.Close()

	log.Printf("embedded redis listening on %s", server.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Printf("embedded redis shutting down")
}
