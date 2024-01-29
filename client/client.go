package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
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
	_, err := c.db.Exec("CREATE TABLE IF NOT EXISTS known_users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL)")
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
		sizeBuf := make([]byte, 10)
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

func (c *ChatClient) requestUserCertIfNotKnown(username string) error {
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

	return c.Send(common.NewCertRequest(username))
}

func (c *ChatClient) saveUserToKnown(username string, certificate []byte) error {
	_, err := c.db.Exec("INSERT INTO known_users (username, certificate) VALUES (?, ?)", username, certificate)
	if err != nil {
		if err.Error() == "UNIQUE constraint failed: known_users.username" {
			return nil
		}
		return err
	}
	return nil
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
		return c.requestUserCertIfNotKnown(msgPublic.Author)
	case common.MsgTypeCertResponse:
		msgKeyResponse, err := common.UnpackFromMsg[common.CertResponse](msg)
		if err != nil {
			return err
		}
		return c.saveUserToKnown(msgKeyResponse.Username, msgKeyResponse.Certificate)
	case common.MsgTypePrivate:
		msgPrivate, err := common.UnpackFromMsg[common.MsgPrivate](msg)
		if err != nil {
			return err
		}
		encryptedText, err := base64.StdEncoding.DecodeString(msgPrivate.Text)
		if err != nil {
			return err
		}
		decryptedText, err := common.RsaDecrypt(c.cert.PrivateKey.(*rsa.PrivateKey), encryptedText)
		if err != nil {
			return err
		}
		log.Infof("[PRIV] [%s] %s: %s", msgPrivate.Timestamp, msgPrivate.Author, decryptedText)
		return nil
	default:
		return fmt.Errorf("unknown msg type: %v", msg)
	}
}

func (c *ChatClient) startInputLoop() {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read input: %s", err)
		}
		input = input[:len(input)-1]

		if input == "/list" {
			msg := common.NewMsg(common.MsgTypeListUsers, nil)
			err := c.Send(msg)
			if err != nil {
				log.Errorf("failed to send message: %s", err)
			}
			continue
		}
		if strings.HasPrefix(input, "/priv") {
			err := c.inputPrivMsg(input)
			if err != nil {
				log.Errorf("failed to send message: %s", err)
			}
			continue
		}

		pubMsg, err := common.NewMsgPublic(c.username, input, c.cert.PrivateKey.(*rsa.PrivateKey))
		if err != nil {
			log.Errorf("failed to create msg: %s", err)
		}
		err = c.Send(pubMsg)
		if err != nil {
			log.Errorf("failed to send message: %s", err)
		}
	}
}

func (c *ChatClient) inputPrivMsg(input string) error {
	parts := strings.Split(input, " ")
	if len(parts) < 3 {
		return errors.New("invalid input")
	}
	recipient := parts[1]
	text := strings.Join(parts[2:], " ")

	if recipient == c.username {
		return errors.New("cannot send private message to yourself")
	}

	row, err := c.db.Query("SELECT certificate FROM known_users WHERE username = ? LIMIT 1", recipient)
	if err != nil {
		return errors.New("database error")
	}
	defer row.Close()

	var certBytes []byte
	if !row.Next() {
		return errors.New("user not found")
	}
	err = row.Scan(&certBytes)

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return errors.New("invalid cert")
	}

	msg, err := common.NewMsgPrivate(c.username, c.cert.PrivateKey.(*rsa.PrivateKey), recipient, cert.PublicKey.(*rsa.PublicKey), text)
	if err != nil {
		return errors.New("failed to create msg")
	}

	return c.Send(msg)
}
