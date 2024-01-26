package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"net"
)

type ChatServer struct {
	Addr string
	Cert tls.Certificate
	db   *sql.DB
}

func NewChatServer(addr string, cert tls.Certificate, db *sql.DB) *ChatServer {
	return &ChatServer{
		Addr: addr,
		Cert: cert,
		db:   db,
	}
}

func (s *ChatServer) Serve() error {
	config := &tls.Config{
		Certificates: []tls.Certificate{s.Cert},
	}
	listener, err := tls.Listen("tcp", s.Addr, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Infof("listening on %s", s.Addr)

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
			if err.Error() == "EOF" {
				log.Infof("connection from %s closed", conn.RemoteAddr())
				return
			}
			log.Errorf("failed to read from %s: %s", conn.RemoteAddr(), err)
			return
		}
		log.Infof("received %d bytes: %s", n, buf[:n])
	}
}

func (s *ChatServer) InitDb() error {
	_, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) NOT NULL)")
	if err != nil {
		return err
	}
	return nil
}

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
