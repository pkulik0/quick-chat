package main

import (
	"encoding/json"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"net"
)

type ChatClient struct {
	conn net.Conn
}

func NewChatClient(conn net.Conn) *ChatClient {
	return &ChatClient{
		conn: conn,
	}
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
	if msg[0] == '/' {
		msgType = common.MsgTypeCmd
		msg = msg[1:]
	}
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
