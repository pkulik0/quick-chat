package common

import (
	"crypto/rsa"
	"crypto/tls"
)

type MsgPublic struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Signature []byte `json:"signature"`
	Timestamp string `json:"timestamp"`
}

func NewMsgPublic(author string, text string, cert *tls.Certificate) (*Msg, error) {
	signature, err := RsaSign(cert.PrivateKey.(*rsa.PrivateKey), []byte(text))
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
