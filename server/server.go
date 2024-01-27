package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"github.com/pkulik0/secure-chat/common"
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

		log.Infof("new connection from %s", conn.RemoteAddr())
		userConn := NewUserConn(conn)
		go userConn.RunWorker()
	}
}

type UserConn struct {
	conn net.Conn
}

func NewUserConn(conn net.Conn) *UserConn {
	return &UserConn{
		conn: conn,
	}
}

func (u *UserConn) RunWorker() {
	defer u.conn.Close()
	for {
		buf := make([]byte, 1024)
		n, err := u.conn.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				log.Infof("connection from %s closed", u.conn.RemoteAddr())
				return
			}
			log.Errorf("failed to read from %s: %s", u.conn.RemoteAddr(), err)
			return
		}
		log.Infof("received %d bytes: %s", n, buf[:n])

		var msgHeader common.MsgHeader
		err = json.Unmarshal(buf[:n], &msgHeader)
		if err != nil {
			log.Errorf("failed to unmarshal msg header: %s", err)
			return
		}

	}
}

func (s *ChatServer) InitDb() error {
	_, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) NOT NULL)")
	if err != nil {
		return err
	}
	return nil
}
