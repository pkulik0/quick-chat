package main

import (
	"crypto/tls"
	"encoding/json"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
)

type ChatClient struct {
	conn *tls.Conn
	cert *tls.Certificate
}

func NewChatClient(conn *tls.Conn, cert *tls.Certificate) *ChatClient {
	return &ChatClient{
		conn: conn,
		cert: cert,
	}
}

func (c *ChatClient) Connect() error {
	data := c.cert.Certificate[0]
	msg := common.MsgHeader{
		Type: common.MsgTypeAuth,
		Data: data,
	}

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

func (c *ChatClient) StartReceiver() {
	for {
		buf := make([]byte, 1024)
		n, err := c.conn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from %s: %s", c.conn.RemoteAddr(), err)
			return
		}

		log.Infof("received %d bytes: %s", n, buf[:n])
	}
}

func (c *ChatClient) Send(msg string) error {
	log.Infof("sending message: %s", msg)

	msgType := common.MsgTypeMsg
	header := common.NewMsgHeader(msgType, msg)

	jsonBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(jsonBytes)
	if err != nil {
		return err
	}
	return nil
}
