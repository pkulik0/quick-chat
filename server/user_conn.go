package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"net"
	"slices"
	"strings"
)

type UserConn struct {
	conn    net.Conn
	server  *ChatServer
	channel chan struct{}

	username string
	cert     *x509.Certificate

	lastSeenMsgId int
}

func NewUserConn(conn net.Conn, server *ChatServer) *UserConn {
	return &UserConn{
		conn:    conn,
		server:  server,
		channel: make(chan struct{}, 1),
	}
}

func (u *UserConn) Close() {
	u.server.unregisterConn(u.username)
	close(u.channel)
	u.conn.Close()
}

func (u *UserConn) Send(msg *common.Msg) error {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = u.conn.Write(msgBytes)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserConn) handleAuthSuccess() error {
	if err := u.server.registerConn(u.username, u.channel); err != nil {
		return err
	}

	welcomeMsg := &common.Msg{
		Type: common.MsgTypeSystem,
		Data: fmt.Sprintf("Welcome, %s!", u.username),
	}
	return u.Send(welcomeMsg)
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

	u.cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		log.Errorf("failed to parse cert: %s", err)
		return errors.New("failed to parse cert")
	}

	if !slices.Contains(u.cert.Subject.Organization, "secure-chat") {
		return errors.New("invalid cert")
	}

	u.username = u.cert.Subject.CommonName

	_, err = u.server.db.Exec("INSERT INTO users (username, certificate) VALUES (?, ?)", u.username, certBytes)
	if err == nil {
		return u.handleAuthSuccess()
	}
	if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		log.Errorf("failed to insert user: %s", err)
		return errors.New("internal error")
	}

	row, err := u.server.db.Query("SELECT certificate FROM users WHERE username = ?", u.username)
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
		return errors.New("username taken or invalid cert")
	}
	return u.handleAuthSuccess()
}

func (u *UserConn) handlePublic(msgPublic *common.MsgPublic) error {
	if err := msgPublic.Verify(u.cert); err != nil {
		log.Errorf("failed to verify msg: %s", err)
		return errors.New("invalid signature")
	}

	_, err := u.server.db.Exec("INSERT INTO public_msgs (author, signature, text) VALUES (?, ?, ?)", msgPublic.Author, msgPublic.Signature, msgPublic.Text)
	if err != nil {
		log.Errorf("failed to insert public msg: %s", err)
		return errors.New("internal error")
	}

	go u.server.notifyAll()

	return nil
}

func (u *UserConn) handleMessage(msg *common.Msg) error {
	switch msg.Type {
	case common.MsgTypeAuth:
		return u.handleAuth(msg.Data)
	case common.MsgTypePublic:
		msgPublic, err := common.MsgPublicFromMsg(msg)
		if err != nil {
			log.Errorf("failed to get msg public: %s", err)
			return errors.New("invalid msg")
		}
		return u.handlePublic(msgPublic)
	}
	return errors.New("unknown message type")
}

func (u *UserConn) RunSendWorker() {
	for {
		_, ok := <-u.channel
		if !ok {
			return
		}

		rows, err := u.server.db.Query("SELECT * FROM public_msgs WHERE id > ?", u.lastSeenMsgId)
		if err != nil {
			log.Errorf("failed to query public msgs: %s", err)
			continue
		}

		var msgs []*common.Msg
		for rows.Next() {
			var id int
			var author string
			var signature []byte
			var text string
			var timestamp string
			err = rows.Scan(&id, &author, &signature, &text, &timestamp)
			if err != nil {
				log.Errorf("failed to scan public msg: %s", err)
				continue
			}
			msgs = append(msgs, common.MsgPublicFromDb(author, text, signature, timestamp))

			if u.lastSeenMsgId < id {
				u.lastSeenMsgId = id
			}
		}

		for _, msg := range msgs {
			err = u.Send(msg)
			if err != nil {
				log.Errorf("failed to send public msg: %s", err)
				continue
			}
		}
	}
}

func (u *UserConn) RunRecvWorker() {
	defer u.Close()
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

		var msg common.Msg
		err = json.Unmarshal(buf[:n], &msg)
		if err != nil {
			log.Errorf("failed to unmarshal msg header: %s", err)
			return
		}

		if err = u.handleMessage(&msg); err != nil {
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
	_, err := s.db.Exec("CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	_, err = s.db.Exec("CREATE TABLE IF NOT EXISTS public_msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, author VARCHAR(64) NOT NULL REFERENCES users(username), signature BLOB NOT NULL, text TEXT NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}

	return nil
}
