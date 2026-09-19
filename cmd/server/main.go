package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"localpki/internal/app"
	"localpki/internal/keystore"
	"localpki/internal/pki"
	"localpki/internal/store"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5224", "HTTP listen address")
	dataDir := flag.String("data", filepath.Join(".", "data"), "persistent data directory")
	webRoot := flag.String("web", filepath.Join(".", "web"), "web asset directory")
	flag.Parse()

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	keys, err := keystore.New(filepath.Join(*dataDir, "keys"))
	if err != nil {
		log.Fatalf("open local key store: %v", err)
	}
	service := pki.NewService(st, keys)
	server := app.New(service, *webRoot)

	log.Printf("local PKI rehearsal server listening on http://%s (data=%s)", *listen, *dataDir)
	httpServer := &http.Server{Addr: *listen, Handler: server.Routes()}
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	_ = os.Stdout.Sync()
}
