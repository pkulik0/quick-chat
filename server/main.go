package main

import (
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
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

	server := NewChatServer(common.LoadCert("server"), db)

	if err := server.InitDb(); err != nil {
		log.Fatalf("failed to initialize db: %s", err)
	}

	if err := server.Serve(*addr); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
