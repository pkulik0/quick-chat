package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
)

type ChatClient struct {
	conn *tls.Conn
	cert *tls.Certificate

	username string
}

func NewChatClient(conn *tls.Conn, cert *tls.Certificate, username string) *ChatClient {
	return &ChatClient{
		conn:     conn,
		cert:     cert,
		username: username,
	}
}

func (c *ChatClient) Send(msg *common.Msg) error {
	jsonBytes, err := json.Marshal(msg)
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
		buf := make([]byte, 1024)
		n, err := c.conn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from %s: %s", c.conn.RemoteAddr(), err)
			return
		}

		msg := &common.Msg{}
		err = json.Unmarshal(buf[:n], msg)
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

func (c *ChatClient) handleMsg(msg *common.Msg) error {
	switch msg.Type {
	case common.MsgTypeSystem:
		log.Infof("system msg: %s", msg.Data)
	case common.MsgTypePublic:
		msgPublic, err := common.MsgPublicFromMsg(msg)
		if err != nil {
			return err
		}
		log.Infof("[%s] %s: %s", msgPublic.Timestamp, msgPublic.Author, msgPublic.Text)
	default:
		return fmt.Errorf("unknown msg type: %v", msg)
	}
	return nil
}

func (c *ChatClient) SendText(text string) error {
	msg := common.NewMsg(common.MsgTypePublic, text)
	return c.Send(msg)
}
