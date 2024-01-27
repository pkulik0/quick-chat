package common

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
