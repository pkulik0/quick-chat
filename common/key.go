package common

func NewKeyRequest(username string) *Msg {
	return &Msg{
		Type: MsgTypeKeyRequest,
		Data: username,
	}
}

type KeyResponse struct {
	Username    string `json:"username"`
	Certificate []byte `json:"certificate"`
}

func NewKeyResponse(username string, certificate []byte) *Msg {
	return &Msg{
		Type: MsgTypeKeyResponse,
		Data: &KeyResponse{
			Username:    username,
			Certificate: certificate,
		},
	}
}
