package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

type PrivRequest struct {
	Sender     string `json:"sender"`
	Recipient  string `json:"recipient"`
	P          []byte `json:"p"`
	G          []byte `json:"g"`
	Result     []byte `json:"result"`
	SenderCert []byte `json:"sender_cert"`
}

const primeBitSize = 2048

func NewPrivRequest(sender string, senderPrivKey *rsa.PrivateKey, recipient string, recipientPubKey *rsa.PublicKey) (*Msg, error) {
	p, err := rand.Prime(rand.Reader, primeBitSize)
	if err != nil {
		return nil, err
	}

	g, err := rand.Prime(rand.Reader, primeBitSize)
	if err != nil {
		return nil, err
	}

	result := new(big.Int).Exp(g, senderPrivKey.D, p).Bytes()
	encryptedResult, err := RsaEncrypt(recipientPubKey, result)
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypePrivRequest,
		Data: &PrivRequest{
			Sender:     sender,
			Recipient:  recipient,
			P:          p.Bytes(),
			G:          g.Bytes(),
			Result:     encryptedResult,
			SenderCert: senderPrivKey.PublicKey.N.Bytes(),
		},
	}, nil
}

func PrivRequestFromDb(sender string, recipient string, p []byte, g []byte, result []byte, senderKey []byte) *PrivRequest {
	return &PrivRequest{
		Sender:     sender,
		Recipient:  recipient,
		P:          p,
		G:          g,
		Result:     result,
		SenderCert: senderKey,
	}
}

func (p *PrivRequest) GetSharedKey(recipientPrivKey *rsa.PrivateKey) ([]byte, error) {
	senderResult, err := RsaDecrypt(recipientPrivKey, p.Result)
	if err != nil {
		return nil, err
	}

	return new(big.Int).Exp(
		new(big.Int).SetBytes(senderResult),
		recipientPrivKey.N,
		new(big.Int).SetBytes(p.P),
	).Bytes(), nil
}

type PrivResponse struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Result    []byte `json:"result"`
	P         []byte `json:"p"`
}

func NewPrivResponse(keyAcceptor *rsa.PrivateKey, request *PrivRequest) (*Msg, error) {
	senderCert, err := x509.ParseCertificate(request.SenderCert)
	if err != nil {
		return nil, err
	}

	p := new(big.Int).SetBytes(request.P)
	g := new(big.Int).SetBytes(request.G)

	result := new(big.Int).Exp(g, keyAcceptor.D, p).Bytes()
	encryptedResult, err := RsaEncrypt(senderCert.PublicKey.(*rsa.PublicKey), result)
	if err != nil {
		return nil, err
	}

	return &Msg{
		Type: MsgTypePrivResponse,
		Data: &PrivResponse{
			Sender:    request.Recipient,
			Recipient: request.Sender,
			Result:    encryptedResult,
			P:         request.P,
		},
	}, nil
}

func PrivResponseFromDb(sender string, recipient string, result []byte, p []byte) *PrivResponse {
	return &PrivResponse{
		Sender:    sender,
		Recipient: recipient,
		Result:    result,
		P:         p,
	}
}

func (p *PrivResponse) GetSharedKey(senderPubKey *rsa.PrivateKey) ([]byte, error) {
	recipientResult, err := RsaDecrypt(senderPubKey, p.Result)
	if err != nil {
		return nil, err
	}

	return new(big.Int).Exp(
		new(big.Int).SetBytes(recipientResult),
		senderPubKey.N,
		new(big.Int).SetBytes(p.P),
	).Bytes(), nil
}
