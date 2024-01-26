package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
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

type MsgType uint8

const (
	MsgTypeCmd  MsgType = 0
	MsgTypeMsg  MsgType = 1
	MsgTypeCert MsgType = 2
)

type MsgHeader struct {
	Type MsgType     `json:"type"`
	Data interface{} `json:"data"`
}

func NewMsgHeader(msgType MsgType, msg interface{}) *MsgHeader {
	return &MsgHeader{
		Type: msgType,
		Data: msg,
	}
}

func (c *ChatClient) Send(msg string) error {
	log.Infof("sending message: %s", msg)

	isCmd := false
	if msg[0] == '/' {
		isCmd = true
		msg = msg[1:]
	}
	msgType := MsgTypeMsg
	if isCmd {
		msgType = MsgTypeCmd
	}
	header := NewMsgHeader(msgType, msg)

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

func main() {
	addr := flag.String("addr", "", "server address")
	flag.Parse()
	if *addr == "" {
		log.Fatalf("must specify server address")
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", *addr, config)
	if err != nil {
		log.Fatalf("failed to connect to %s: %s", *addr, err)
	}
	defer conn.Close()

	client := NewChatClient(conn)
	go client.StartReceiver()

	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read input: %s", err)
		}

		err = client.Send(input)
		if err != nil {
			log.Fatalf("failed to send message: %s", err)
		}
	}
}
