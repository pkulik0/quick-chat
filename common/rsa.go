package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func RsaSign(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
}

func RsaVerify(publicKey *rsa.PublicKey, signature []byte, data []byte) error {
	hash := sha256.New()
	hash.Write(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash.Sum(nil), signature)
}

func RsaEncrypt(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func RsaDecrypt(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}
