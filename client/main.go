package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/pkulik0/secure-chat/common"
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {
	addr := flag.String("addr", "", "server address")
	username := flag.String("username", "", "username")
	flag.Parse()
	if *addr == "" {
		log.Fatalf("must specify server address")
	}
	if *username == "" {
		log.Fatalf("must specify username")
	}

	certFile := fmt.Sprintf("cert_%s.pem", *username)
	keyFile := fmt.Sprintf("key_%s.pem", *username)
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Infof("no key/cert found, generating new ones")
		if err := common.GenerateCert(*username, keyFile, certFile); err != nil {
			log.Fatalf("failed to generate cert: %s", err)
		}
	}

	cert, err := common.LoadCert(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", *addr, config)
	if err != nil {
		log.Fatalf("failed to connect to %s: %s", *addr, err)
	}
	defer conn.Close()

	client := NewChatClient(conn, &cert, *username)
	go client.StartReceiver()

	if err := client.Connect(); err != nil {
		log.Fatalf("failed to connect: %s", err)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read input: %s", err)
		}
		input = input[:len(input)-1]

		log.Debugf("input: '%v'", input)
		if input == "/list" {
			msg := common.NewMsg(common.MsgTypeListUsers, nil)
			err := client.Send(msg)
			if err != nil {
				log.Fatalf("failed to send message: %s", err)
			}
			continue
		}

		pubMsg, err := common.NewMsgPublic(client.username, input, client.cert)
		if err != nil {
			log.Fatalf("failed to create msg: %s", err)
		}
		err = client.Send(pubMsg)
		if err != nil {
			log.Fatalf("failed to send message: %s", err)
		}
	}
}
