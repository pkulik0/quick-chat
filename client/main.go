package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	log "github.com/sirupsen/logrus"
	"os"
)

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
		input = input[:len(input)-1]

		err = client.Send(input)
		if err != nil {
			log.Fatalf("failed to send message: %s", err)
		}
	}
}
