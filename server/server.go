package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sync"
)

type ChatServer struct {
	Addr string
	Cert tls.Certificate
	db   *sql.DB

	connections map[string]chan struct{}
	mutex       sync.Mutex
}

func NewChatServer(addr string, cert tls.Certificate, db *sql.DB) *ChatServer {
	return &ChatServer{
		Addr:        addr,
		Cert:        cert,
		db:          db,
		connections: make(map[string]chan struct{}),
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
		go userConn.RunRecvWorker()
		go userConn.RunSendWorker()
	}
}

func (s *ChatServer) registerConn(username string, channel chan struct{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.connections[username]; ok {
		return fmt.Errorf("user %s already connected", username)
	}
	s.connections[username] = channel
	return nil
}

func (s *ChatServer) unregisterConn(username string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.connections, username)
}

func (s *ChatServer) notify(username string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	log.Printf("Notifying %s", username)
	if _, ok := s.connections[username]; !ok {
		return fmt.Errorf("user %s is not connected", username)
	}
	s.connections[username] <- struct{}{}
	return nil
}

func (s *ChatServer) notifyAll() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for conn, channel := range s.connections {
		log.Printf("Notifying: %s", conn)
		channel <- struct{}{}
	}
}
