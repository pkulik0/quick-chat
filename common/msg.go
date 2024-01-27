package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
)

type MsgType uint8

const (
	MsgTypeAuth   MsgType = 0
	MsgTypeSystem MsgType = 1
	MsgTypePublic MsgType = 2
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

func (m *MsgPublic) Verify(cert *x509.Certificate) error {
	hash := sha256.New()
	hash.Write([]byte(m.Text))
	return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), m.Signature)
}
