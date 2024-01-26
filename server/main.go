package main

import (
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"net"
)

type ChatServer struct {
	Addr string
	db   *sql.DB
}

func NewChatServer() *ChatServer {
	addr := flag.String("addr", ":30050", "address to serve on")
	flag.Parse()

	db, err := sql.Open("sqlite3", "file:server.db?cache?shared")
	db.SetMaxOpenConns(1)
	if err != nil {
		log.Fatalf("failed to open db: %s", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping db: %s", err)
	}

	return &ChatServer{
		Addr: *addr,
		db:   db,
	}
}

func (s *ChatServer) Listen() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("failed to accept conn: %s", err)
		}
		go s.handleConn(conn)
	}
}

func (s *ChatServer) handleConn(conn net.Conn) {
	defer conn.Close()
	log.Infof("new connection from %s", conn.RemoteAddr())

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from %s: %s", conn.RemoteAddr(), err)
			return
		}
		log.Infof("received %d bytes: %s", n, buf[:n])
	}
}

func main() {
	log.Infof("secure-chat server started")

	server := NewChatServer()
	if err := server.Listen(); err != nil {
		log.Fatalf("failed to listen: %s", err)
	}
}
