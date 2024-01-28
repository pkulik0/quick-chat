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
	_, err := c.db.Exec("CREATE TABLE IF NOT EXISTS known_users (username VARCHAR(64) PRIMARY KEY, certificate BLOB NOT NULL, encr_shared_key BLOB)")
	if err != nil {
		return err
	}

	return nil
}

func (c *ChatClient) Send(msg *common.Msg) error {
	log.Infof("Sending msg: %v", msg)
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

	log.Infof("requesting cert for %s", username)
	return c.Send(common.NewCertRequest(username))
}

func (c *ChatClient) saveUserToKnown(username string, certificate []byte, sendRequest bool) error {
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

	if !sendRequest {
		return nil
	}

	msg, err := common.NewPrivRequest(c.username, c.cert.PrivateKey.(*rsa.PrivateKey), username, recipientCert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return err
	}
	return c.Send(msg)
}

func (c *ChatClient) saveSharedKey(sharedKey []byte, username string) error {
	//encryptedSharedKey, err := common.RsaEncrypt(c.cert.Leaf.PublicKey.(*rsa.PublicKey), sharedKey)
	//if err != nil {
	//	return err
	//}

	_, err := c.db.Exec("UPDATE known_users SET encr_shared_key = ? WHERE username = ?", sharedKey, username)
	return err
}

func (c *ChatClient) handlePrivRequest(request *common.PrivRequest) error {
	if err := c.saveUserToKnown(request.Sender, request.SenderCert, false); err != nil {
		return err
	}

	msg, err := common.NewPrivResponse(c.cert.PrivateKey.(*rsa.PrivateKey), request)
	if err != nil {
		return err
	}

	err = c.Send(msg)
	if err != nil {
		return err
	}

	sharedKey, err := request.GetSharedKey(c.cert.PrivateKey.(*rsa.PrivateKey))
	if err != nil {
		return err
	}
	return c.saveSharedKey(sharedKey, request.Sender)
}

func (c *ChatClient) handlePrivResponse(accept *common.PrivResponse) error {
	sharedKey, err := accept.GetSharedKey(c.cert.PrivateKey.(*rsa.PrivateKey))
	if err != nil {
		return err
	}

	err = c.saveSharedKey(sharedKey, accept.Sender)
	if err != nil {
		return err
	}

	return c.Send(&common.Msg{
		Type: common.MsgTypePrivFinalize,
		Data: accept.Sender,
	})
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
		return c.saveUserToKnown(msgKeyResponse.Username, msgKeyResponse.Certificate, true)
	case common.MsgTypePrivRequest:
		privRequest, err := common.UnpackFromMsg[common.PrivRequest](msg)
		log.Infof("Got priv request %s -> %s", privRequest.Sender, privRequest.Recipient)
		if err != nil {
			return err
		}
		return c.handlePrivRequest(privRequest)
	case common.MsgTypePrivResponse:
		privResponse, err := common.UnpackFromMsg[common.PrivResponse](msg)
		log.Infof("Got priv response %s -> %s", privResponse.Sender, privResponse.Recipient)
		if err != nil {
			return err
		}
		return c.handlePrivResponse(privResponse)
	default:
		return fmt.Errorf("unknown msg type: %v", msg)
	}
}
