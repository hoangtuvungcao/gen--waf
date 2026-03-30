package main

import (
	"flag"
	"log"
	"net/http"

	"genwaf/internal/brain"
)

func main() {
	listenAddr := flag.String("listen", ":9091", "HTTP listen address")
	flag.Parse()

	log.Printf("genbrain listening on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, brain.Handler()); err != nil {
		log.Fatalf("serve genbrain: %v", err)
	}
}
