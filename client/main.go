package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	log.Infof("secure-chat client started")

	addr := flag.String("addr", "", "server address")
	username := flag.String("username", "", "username")
	flag.Parse()
	if *addr == "" {
		log.Fatalf("must specify server address")
	}
	if *username == "" {
		log.Fatalf("must specify username")
	}

	db, err := sql.Open("sqlite3", "file:client.db?cache?shared")
	if err != nil {
		log.Fatalf("failed to open db: %s", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping db: %s", err)
	}
	defer db.Close()

	conn, err := tls.Dial("tcp", *addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("failed to connect to %s: %s", *addr, err)
	}
	defer conn.Close()

	client := NewChatClient(conn, common.LoadCert(*username), db, *username)
	if err := client.InitDb(); err != nil {
		log.Fatalf("failed to initialize db: %s", err)
	}

	go client.StartReceiver()
	if err := client.Connect(); err != nil {
		log.Fatalf("failed to connect: %s", err)
	}

	client.startInputLoop()
}
