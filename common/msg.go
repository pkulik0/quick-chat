package common

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
)

type MsgType uint8

const (
	MsgTypeAuth         MsgType = 0
	MsgTypeSystem       MsgType = 1
	MsgTypePublic       MsgType = 2
	MsgTypePrivate      MsgType = 3
	MsgTypeListUsers    MsgType = 4
	MsgTypeCertRequest  MsgType = 5
	MsgTypeCertResponse MsgType = 6
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

func UnpackFromMsg[T any](msg *Msg) (*T, error) {
	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		return nil, err
	}

	var data T
	err = json.Unmarshal(jsonData, &data)
	return &data, err
}

type MsgPublic struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Signature []byte `json:"signature"`
	Timestamp string `json:"timestamp"`
}

func NewMsgPublic(author string, text string, privateKey *rsa.PrivateKey) (*Msg, error) {
	signature, err := RsaSign(privateKey, []byte(text))
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

type MsgPrivate struct {
	MsgPublic
	Recipient string `json:"recipient"`
}

func NewMsgPrivate(author string, keyAuthor *rsa.PrivateKey, recipient string, recipientKey *rsa.PublicKey, text string) (*Msg, error) {
	encryptedText, err := RsaEncrypt(recipientKey, []byte(text))
	if err != nil {
		return nil, err
	}

	signature, err := RsaSign(keyAuthor, encryptedText)
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypePrivate,
		Data: &MsgPrivate{
			MsgPublic: MsgPublic{
				Author:    author,
				Text:      base64.StdEncoding.EncodeToString(encryptedText),
				Signature: signature,
			},
			Recipient: recipient,
		},
	}, nil
}

func MsgPrivateFromDb(author string, signature []byte, recipient string, text string, timestamp string) *Msg {
	return &Msg{
		Type: MsgTypePrivate,
		Data: &MsgPrivate{
			MsgPublic: MsgPublic{
				Author:    author,
				Text:      text,
				Signature: signature,
				Timestamp: timestamp,
			},
			Recipient: recipient,
		},
	}
}
