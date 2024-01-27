package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"os"
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

	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		log.Infof("no key/cert found, generating new ones")
		if err := common.GenerateCert("server", "key.pem", "cert.pem"); err != nil {
			log.Fatalf("failed to generate cert: %s", err)
		}
	}

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}

	server := NewChatServer(*addr, cert, db)

	if err := server.InitDb(); err != nil {
		log.Fatalf("failed to initialize db: %s", err)
	}

	if err := server.Serve(); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
