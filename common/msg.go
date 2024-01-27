package common

import "encoding/json"

type MsgType uint8

const (
	MsgTypeAuth                MsgType = 0
	MsgTypeSystem              MsgType = 1
	MsgTypePublic              MsgType = 2
	MsgTypePrivate             MsgType = 3
	MsgTypeListUsers           MsgType = 4
	MsgTypeConversationRequest MsgType = 5
	MsgTypeConversationAccept  MsgType = 6
	MsgTypeKeyRequest          MsgType = 7
	MsgTypeKeyResponse         MsgType = 8
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
