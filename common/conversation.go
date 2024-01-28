package common

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

type ConversationRequest struct {
	From   string `json:"from"`
	To     string `json:"to"`
	P      []byte `json:"p"`
	G      []byte `json:"g"`
	Result []byte `json:"result"`
}

const primeBitSize = 2048

func calcFinalResult(result *big.Int, P *big.Int, key []byte) *big.Int {
	return new(big.Int).Exp(
		result,
		new(big.Int).SetBytes(key),
		P,
	)
}

func calcPartialResult(G *big.Int, P *big.Int, key []byte) *big.Int {
	return new(big.Int).Exp(
		G,
		new(big.Int).SetBytes(key),
		P,
	)
}

func NewConversationRequest(fromUsername string, keyFrom *rsa.PrivateKey, toUsername string, keyTo *rsa.PublicKey) (*Msg, error) {
	p, err := rand.Prime(rand.Reader, primeBitSize)
	if err != nil {
		return nil, err
	}

	g, err := rand.Prime(rand.Reader, primeBitSize)
	if err != nil {
		return nil, err
	}

	result := calcPartialResult(g, p, keyFrom.D.Bytes()).Bytes()
	encryptedResult, err := RsaEncrypt(keyTo, result)
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypeConversationRequest,
		Data: &ConversationRequest{
			From:   fromUsername,
			To:     toUsername,
			P:      p.Bytes(),
			G:      g.Bytes(),
			Result: encryptedResult,
		},
	}, nil
}

func (r *ConversationRequest) GetSharedKey(acceptorKey *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	partialResult, err := RsaDecrypt(acceptorKey, r.Result)
	if err != nil {
		return nil, err
	}

	result := calcFinalResult(
		new(big.Int).SetBytes(partialResult),
		new(big.Int).SetBytes(r.P),
		acceptorKey.N.Bytes(),
	)

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: acceptorKey.N,
			E: acceptorKey.E,
		},
		D: result,
	}, nil

}

type ConversationAccept struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Result []byte `json:"result"`
}

func NewConversationAccept(keyRequestor *rsa.PublicKey, keyAcceptor *rsa.PrivateKey, request *ConversationRequest) (*Msg, error) {
	p := new(big.Int).SetBytes(request.P)
	g := new(big.Int).SetBytes(request.G)
	result, err := RsaEncrypt(keyRequestor, calcPartialResult(g, p, keyAcceptor.N.Bytes()).Bytes())
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypeConversationAccept,
		Data: &ConversationAccept{
			From:   request.To,
			To:     request.From,
			Result: result,
		},
	}, nil
}
