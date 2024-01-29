package main

import (
	"crypto/rsa"
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

type Conn struct {
	conn    net.Conn
	server  *ChatServer
	channel chan struct{}

	username string
	cert     *x509.Certificate

	lastSeenMsgId int
}

func NewConn(conn net.Conn, server *ChatServer) *Conn {
	return &Conn{
		conn:    conn,
		server:  server,
		channel: make(chan struct{}, 1),
	}
}

func (u *Conn) Close() {
	u.server.unregisterConn(u.username)
	close(u.channel)
	u.conn.Close()
}

func (u *Conn) Send(msg *common.Msg) error {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = u.conn.Write([]byte(fmt.Sprintf("%d\n", len(msgBytes))))
	if err != nil {
		return err
	}

	_, err = u.conn.Write(msgBytes)
	if err != nil {
		return err
	}

	return nil
}

func (u *Conn) handleAuthSuccess() error {
	if err := u.server.registerConn(u.username, u.channel); err != nil {
		return err
	}

	welcomeMsg := &common.Msg{
		Type: common.MsgTypeSystem,
		Data: fmt.Sprintf("Welcome, %s!", u.username),
	}
	return u.Send(welcomeMsg)
}

func (u *Conn) handleAuth(data interface{}) error {
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

func (u *Conn) handlePublic(msgPublic *common.MsgPublic) error {
	if err := common.RsaVerify(u.cert.PublicKey.(*rsa.PublicKey), msgPublic.Signature, []byte(msgPublic.Text)); err != nil {
		log.Errorf("failed to verify msg sig: %s", err)
		return errors.New("invalid signature")
	}

	_, err := u.server.db.Exec("INSERT INTO msgs (sender, signature, text) VALUES (?, ?, ?)", msgPublic.Author, msgPublic.Signature, msgPublic.Text)
	if err != nil {
		log.Errorf("failed to insert public msg: %s", err)
		return errors.New("internal error")
	}

	go u.server.notifyAll()

	return nil
}

func (u *Conn) handlePrivate(msgPrivate *common.MsgPrivate) error {
	encryptedText, err := base64.StdEncoding.DecodeString(msgPrivate.Text)
	if err != nil {
		log.Errorf("failed to decode encrypted text: %s", err)
		return errors.New("invalid encrypted text")
	}

	if err := common.RsaVerify(u.cert.PublicKey.(*rsa.PublicKey), msgPrivate.Signature, encryptedText); err != nil {
		log.Errorf("failed to verify msg sig: %s", err)
		return errors.New("invalid signature")
	}

	_, err = u.server.db.Exec("INSERT INTO msgs (sender, signature, recipient, text) VALUES (?, ?, ?, ?)", msgPrivate.Author, msgPrivate.Signature, msgPrivate.Recipient, msgPrivate.Text)
	if err != nil {
		log.Errorf("failed to insert public msg: %s", err)
		return errors.New("internal error")
	}

	u.server.notify(msgPrivate.Recipient)

	return nil
}

func (u *Conn) requestPublicKeyFor(username string) error {
	if username == u.username {
		return errors.New("cannot request own key")
	}

	row, err := u.server.db.Query("SELECT certificate FROM users WHERE username = ? LIMIT 1", username)
	if err != nil {
		log.Errorf("failed to query user: %s", err)
		return errors.New("internal error")
	}
	defer row.Close()

	var certBytes []byte
	if !row.Next() {
		return errors.New("user not found")
	}
	err = row.Scan(&certBytes)
	if err != nil {
		log.Errorf("failed to scan user: %s", err)
		return errors.New("internal error")
	}

	return u.Send(&common.Msg{
		Type: common.MsgTypeCertResponse,
		Data: &common.CertResponse{
			Username:    username,
			Certificate: certBytes,
		},
	})
}

func (u *Conn) handleMessage(msg *common.Msg) error {
	switch msg.Type {
	case common.MsgTypeAuth:
		return u.handleAuth(msg.Data)
	case common.MsgTypePublic:
		msgPublic, err := common.UnpackFromMsg[common.MsgPublic](msg)
		if err != nil {
			log.Errorf("failed to get msg public: %s", err)
			return errors.New("invalid msg")
		}
		return u.handlePublic(msgPublic)
	case common.MsgTypeListUsers:
		users := strings.Join(u.server.listUsers(), ", ")
		return u.Send(&common.Msg{
			Type: common.MsgTypeSystem,
			Data: fmt.Sprintf("Users online: %s", users),
		})
	case common.MsgTypeCertRequest:
		username, ok := msg.Data.(string)
		if !ok {
			return errors.New("invalid username")
		}
		log.Infof("Got key request: %s -> %s", u.username, username)
		return u.requestPublicKeyFor(username)
	case common.MsgTypePrivate:
		msgPrivate, err := common.UnpackFromMsg[common.MsgPrivate](msg)
		if err != nil {
			log.Errorf("failed to get msg private: %s", err)
			return errors.New("invalid msg")
		}
		log.Infof("Got private msg: %s -> %s", msgPrivate.Author, msgPrivate.Recipient)
		return u.handlePrivate(msgPrivate)
	default:
		return errors.New("invalid msg type")
	}
}

func (u *Conn) RunSendWorker() {
	for {
		_, ok := <-u.channel
		if !ok {
			return
		}

		func() {
			rows, err := u.server.db.Query("SELECT id, sender, signature, recipient, text, timestamp FROM msgs WHERE id > ? AND (recipient IS NULL OR recipient = ?)", u.lastSeenMsgId, u.username)
			if err != nil {
				log.Errorf("failed to query public msgs: %s", err)
				return
			}
			defer rows.Close()

			var msgs []*common.Msg
			for rows.Next() {
				var id int
				var sender string
				var signature []byte
				var recipient *string
				var text string
				var timestamp string
				err = rows.Scan(&id, &sender, &signature, &recipient, &text, &timestamp)
				if err != nil {
					log.Errorf("failed to scan public msg: %s", err)
					continue
				}

				if recipient == nil {
					msgs = append(msgs, common.MsgPublicFromDb(sender, text, signature, timestamp))
				} else {
					msgs = append(msgs, common.MsgPrivateFromDb(sender, signature, *recipient, text, timestamp))
				}

				if u.lastSeenMsgId < id {
					u.lastSeenMsgId = id
				}
			}

			for _, msg := range msgs {
				err = u.Send(msg)
				if err != nil {
					log.Errorf("failed to send msg: %s", err)
					continue
				}
			}
		}()
	}
}

func (u *Conn) RunRecvWorker() {
	defer u.Close()

	for {
		sizeBuf := make([]byte, 10)
		_, err := u.conn.Read(sizeBuf)
		if err != nil {
			log.Errorf("failed to read from %s: %s", u.conn.RemoteAddr(), err)
			return
		}
		var size int
		_, err = fmt.Sscanf(string(sizeBuf), "%d", &size)

		buf := make([]byte, size)
		occupied := 0
		for occupied < size {
			n, err := u.conn.Read(buf)
			if err != nil {
				log.Errorf("failed to read from %s: %s", u.conn.RemoteAddr(), err)
				return
			}
			occupied += n
		}

		var msg common.Msg
		err = json.Unmarshal(buf, &msg)
		if err != nil {
			log.Errorf("failed to unmarshal msg header: %s", err)
			return
		}

		if err = u.handleMessage(&msg); err != nil {
			err := u.Send(&common.Msg{
				Type: common.MsgTypeSystem,
				Data: err.Error(),
			})
			if err != nil {
				log.Errorf("failed to write error msg: %s", err)
			}
			return
		}
	}
}
