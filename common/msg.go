package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
)

type MsgType uint8

const (
	MsgTypeAuth      MsgType = 0
	MsgTypeSystem    MsgType = 1
	MsgTypePublic    MsgType = 2
	MsgTypePrivate   MsgType = 3
	MsgTypeListUsers MsgType = 4
)

type Msg struct {
	Type MsgType     `json:"type"`
	Data interface{} `json:"data"`
}

func NewMsg(msgType MsgType, msg interface{}) *Msg {
	return &Msg{
		Type: msgType,
		Data: msg,
	}
}

type MsgPublic struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Signature []byte `json:"signature"`
	Timestamp string `json:"timestamp"`
}

func NewMsgPublic(author string, text string, cert *tls.Certificate) (*Msg, error) {
	hash := sha256.New()
	hash.Write([]byte(text))
	signature, err := rsa.SignPKCS1v15(rand.Reader, cert.PrivateKey.(*rsa.PrivateKey), crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypePublic,
		Data: &MsgPublic{
			Author:    author,
			Text:      text,
			Signature: signature,
		},
	}, nil
}

func MsgPublicFromDb(author string, text string, signature []byte, timestamp string) *Msg {
	return &Msg{
		Type: MsgTypePublic,
		Data: &MsgPublic{
			Author:    author,
			Text:      text,
			Signature: signature,
			Timestamp: timestamp,
		},
	}
}

func MsgPublicFromMsg(msg *Msg) (*MsgPublic, error) {
	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		return nil, err
	}

	var msgPublic *MsgPublic
	err = json.Unmarshal(jsonData, &msgPublic)
	return msgPublic, err
}

func (m *MsgPublic) Verify(cert *x509.Certificate) error {
	hash := sha256.New()
	hash.Write([]byte(m.Text))
	return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), m.Signature)
}
