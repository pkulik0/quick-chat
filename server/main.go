package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

const (
	keyFile  = "keys/key.pem"
	certFile = "keys/cert.pem"
)

func main() {
	log.Infof("secure-chat server started")

	addr := flag.String("addr", ":30500", "address to serve on")
	flag.Parse()

	db, err := sql.Open("sqlite3", "file:server.db?cache?shared")
	db.SetMaxOpenConns(1)
	if err != nil {
		log.Fatalf("failed to open db: %s", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping db: %s", err)
	}
	defer db.Close()

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Infof("no key/cert found, generating new ones")
		if err := os.Mkdir("keys", 0700); err != nil && !os.IsExist(err) {
			log.Fatalf("failed to create keys directory: %s", err)
		}
		if err := common.GenerateCert("server", keyFile, certFile); err != nil {
			log.Fatalf("failed to generate cert: %s", err)
		}
		time.Sleep(1 * time.Second) // wait for cert to be written to disk
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}

	server := NewChatServer(&cert, db)

	if err := server.InitDb(); err != nil {
		log.Fatalf("failed to initialize db: %s", err)
	}

	if err := server.Serve(*addr); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
