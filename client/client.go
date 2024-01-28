package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
)

type ChatClient struct {
	conn *tls.Conn
	cert *tls.Certificate
	db   *sql.DB

	username string
}

func NewChatClient(conn *tls.Conn, cert *tls.Certificate, db *sql.DB, username string) *ChatClient {
	return &ChatClient{
		conn:     conn,
		cert:     cert,
		db:       db,
		username: username,
	}
}

func (c *ChatClient) InitDb() error {
	_, err := c.db.Exec("CREATE TABLE IF NOT EXISTS known_users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL, conversation INTEGER REFERENCES conversations(id))")
	if err != nil {
		return err
	}

	return nil
}

func (c *ChatClient) Send(msg *common.Msg) error {
	jsonBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = c.conn.Write([]byte(fmt.Sprintf("%d\n", len(jsonBytes))))
	if err != nil {
		return err
	}

	_, err = c.conn.Write(jsonBytes)
	if err != nil {
		return err
	}

	return nil
}

func (c *ChatClient) Connect() error {
	cert := base64.StdEncoding.EncodeToString(c.cert.Certificate[0])
	msg := common.NewMsg(common.MsgTypeAuth, cert)
	return c.Send(msg)
}

func (c *ChatClient) StartReceiver() {
	for {
		sizeBuf := make([]byte, 32)
		_, err := c.conn.Read(sizeBuf)
		if err != nil {
			log.Errorf("failed to read from %s: %s", c.conn.RemoteAddr(), err)
			return
		}
		var size int
		_, err = fmt.Sscanf(string(sizeBuf), "%d", &size)

		buf := make([]byte, size)
		occupied := 0
		for occupied < size {
			n, err := c.conn.Read(buf)
			if err != nil {
				log.Errorf("failed to read from %s: %s", c.conn.RemoteAddr(), err)
				return
			}
			occupied += n
		}

		msg := &common.Msg{}
		err = json.Unmarshal(buf, msg)
		if err != nil {
			log.Errorf("failed to unmarshal msg: %s", err)
			continue
		}

		err = c.handleMsg(msg)
		if err != nil {
			log.Errorf("failed to handle msg: %s", err)
			continue
		}
	}
}

func (c *ChatClient) requestUserKeyIfNotKnown(username string) error {
	if username == c.username {
		return nil
	}

	row, err := c.db.Query("SELECT certificate FROM known_users WHERE username = ? LIMIT 1", username)
	if err != nil {
		return err
	}
	defer row.Close()
	if row.Next() {
		var certificate []byte
		return row.Scan(&certificate)
	}

	log.Infof("requesting public key for %s", username)
	return c.Send(common.NewKeyRequest(username))
}

func (c *ChatClient) saveUserToKnown(username string, certificate []byte) error {
	_, err := c.db.Exec("INSERT INTO known_users (username, certificate) VALUES (?, ?)", username, certificate)
	if err != nil {
		if err.Error() == "UNIQUE constraint failed: known_users.username" {
			return nil
		}
		return err
	}

	recipientCert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}

	msg, err := common.NewConversationRequest(c.username, c.cert.PrivateKey.(*rsa.PrivateKey), username, recipientCert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return err
	}
	return c.Send(msg)
}

func (c *ChatClient) handleMsg(msg *common.Msg) error {
	switch msg.Type {
	case common.MsgTypeSystem:
		log.Infof("[SYSTEM] %s", msg.Data)
		return nil
	case common.MsgTypePublic:
		msgPublic, err := common.UnpackFromMsg[common.MsgPublic](msg)
		if err != nil {
			return err
		}
		log.Infof("[%s] %s: %s", msgPublic.Timestamp, msgPublic.Author, msgPublic.Text)
		return c.requestUserKeyIfNotKnown(msgPublic.Author)
	case common.MsgTypeKeyResponse:
		msgKeyResponse, err := common.UnpackFromMsg[common.KeyResponse](msg)
		if err != nil {
			return err
		}
		return c.saveUserToKnown(msgKeyResponse.Username, msgKeyResponse.Certificate)
	default:
		return fmt.Errorf("unknown msg type: %v", msg)
	}
}

func (c *ChatClient) SendText(text string) error {
	msg := common.NewMsg(common.MsgTypePublic, text)
	return c.Send(msg)
}
