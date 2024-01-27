package common

type MsgType uint8

const (
	MsgTypeAuth   MsgType = 0
	MsgTypeSystem MsgType = 1
	MsgTypeMsg    MsgType = 2
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
