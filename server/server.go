package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"net"
	"slices"
	"strings"
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
		userConn := NewUserConn(conn, s)
		go userConn.RunWorker()
	}
}

func (s *ChatServer) authenticateUser(certBytes []byte) error {
	certObj, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	log.Infof("cert subject: %+v", certObj)
	return nil
}

type UserConn struct {
	conn   net.Conn
	server *ChatServer
}

func NewUserConn(conn net.Conn, server *ChatServer) *UserConn {
	return &UserConn{
		conn:   conn,
		server: server,
	}
}

func (u *UserConn) handleAuth(data interface{}) error {
	certStr, ok := data.(string)
	if !ok {
		return errors.New("invalid cert")
	}

	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		log.Errorf("failed to decode cert: %s", err)
		return errors.New("invalid cert")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Errorf("failed to parse cert: %s", err)
		return errors.New("failed to parse cert")
	}

	if !slices.Contains(cert.Subject.Organization, "secure-chat") {
		return errors.New("invalid cert")
	}

	username := cert.Subject.CommonName
	_, err = u.server.db.Exec("INSERT INTO users (username, certificate) VALUES (?, ?)", username, certBytes)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		log.Errorf("failed to insert user: %s", err)
		return errors.New("internal error")
	}

	row, err := u.server.db.Query("SELECT certificate FROM users WHERE username = ?", username)
	if err != nil {
		log.Errorf("failed to query user: %s", err)
		return errors.New("internal error")
	}
	defer row.Close()

	var certBytesFromDb []byte
	for row.Next() {
		err = row.Scan(&certBytesFromDb)
		if err != nil {
			log.Errorf("failed to scan user: %s", err)
			return errors.New("internal error")
		}
	}

	if !slices.Equal(certBytes, certBytesFromDb) {
		return errors.New("invalid cert")
	}

	return nil
}

func (u *UserConn) handleMessage(msg *common.MsgHeader) error {
	switch msg.Type {
	case common.MsgTypeAuth:
		return u.handleAuth(msg.Data)
	}
	return errors.New("unknown message type")
}

func (u *UserConn) RunWorker() {
	defer u.conn.Close()
	for {
		buf := make([]byte, 4096)
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

		if err = u.handleMessage(&msgHeader); err != nil {
			_, err := u.conn.Write([]byte(err.Error()))
			if err != nil {
				log.Errorf("failed to write error: %s", err)
				return
			}
			return
		}
	}
}

func (s *ChatServer) InitDb() error {
	_, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL)")
	if err != nil {
		return err
	}
	return nil
}
