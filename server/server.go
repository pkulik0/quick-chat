package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"sync"
)

type ChatServer struct {
	cert *tls.Certificate
	db   *sql.DB

	connections map[string]chan struct{}
	mutex       sync.Mutex
}

func NewChatServer(cert *tls.Certificate, db *sql.DB) *ChatServer {
	return &ChatServer{
		cert:        cert,
		db:          db,
		connections: make(map[string]chan struct{}),
	}
}

func (s *ChatServer) InitDb() error {
	_, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	_, err = s.db.Exec("CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, users [2]VARCHAR(64) NOT NULL REFERENCES users(username), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	_, err = s.db.Exec("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, sender VARCHAR(64) NOT NULL REFERENCES users(username), recipient VARCHAR(64) NOT NULL REFERENCES users(username), p BLOB NOT NULL, g BLOB NOT NULL, sender_encr_result BLOB NOT NULL, recipient_encr_result BLOB, is_finalized BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	_, err = s.db.Exec("CREATE TABLE IF NOT EXISTS msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation INTEGER REFERENCES conversations(id) DEFAULT NULL, author VARCHAR(64) NOT NULL REFERENCES users(username), signature BLOB NOT NULL, text TEXT NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	return nil
}

func (s *ChatServer) Serve(addr string) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{*s.cert},
	}
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Infof("listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("failed to accept conn: %s", err)
		}

		log.Infof("new connection from %s", conn.RemoteAddr())
		userConn := NewConn(conn, s)
		go userConn.RunRecvWorker()
		go userConn.RunSendWorker()
	}
}

func (s *ChatServer) listUsers() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	log.Printf("Listing users (%d) %v", len(s.connections), s.connections)

	i := 0
	users := make([]string, len(s.connections))
	for username, _ := range s.connections {
		users[i] = username
		i++
	}
	return users
}

func (s *ChatServer) registerConn(username string, channel chan struct{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	log.Printf("Registering %s", username)

	if _, ok := s.connections[username]; ok {
		return fmt.Errorf("user %s already connected", username)
	}
	s.connections[username] = channel
	channel <- struct{}{}

	return nil
}

func (s *ChatServer) unregisterConn(username string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	log.Printf("Unregistering %s", username)

	delete(s.connections, username)
}

func (s *ChatServer) notify(username string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.connections[username]; ok {
		log.Printf("Notifying %s", username)
		s.connections[username] <- struct{}{}
	}
}

func (s *ChatServer) notifyAll() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	log.Println("Notifying all")
	for _, channel := range s.connections {
		channel <- struct{}{}
	}
}

func (s *ChatServer) handlePrivRequest(request *common.PrivRequest) error {
	_, err := s.db.Exec("INSERT INTO requests (sender, recipient, p, g, sender_encr_result) VALUES (?, ?, ?, ?, ?)", request.Sender, request.Recipient, request.P, request.G, request.Result)
	if err != nil {
		return err
	}
	s.notify(request.Recipient)
	return nil
}

func (s *ChatServer) handlePrivResponse(accept *common.PrivResponse) error {
	_, err := s.db.Exec("UPDATE requests SET recipient_encr_result = ? WHERE sender = ? AND recipient = ?", accept.Result, accept.Recipient, accept.Sender)
	if err != nil {
		return err
	}
	s.notify(accept.Recipient)
	return nil
}

func (s *ChatServer) handlePrivFinalize(sender string, recipient string) error {
	_, err := s.db.Exec("UPDATE requests SET is_finalized = TRUE WHERE sender = ? AND recipient = ?", sender, recipient)
	return err
}
