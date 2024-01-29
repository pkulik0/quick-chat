package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math/big"
	"os"
	"time"
)

const rsaKeySize = 4096

func GenerateCert(commonName string, keyPath string, certPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"secure-chat"},
		},
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	_, err = keyFile.Write(keyPem)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	_, err = certFile.Write(certPem)

	return nil
}

func LoadCert(suffix string) *tls.Certificate {
	if err := os.Mkdir("keys", 0700); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to create keys directory: %s", err)
	}
	certFile := fmt.Sprintf("keys/cert_%s.pem", suffix)
	keyFile := fmt.Sprintf("keys/key_%s.pem", suffix)
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Infof("no key/cert found, generating new ones")
		if err := GenerateCert(suffix, keyFile, certFile); err != nil {
			log.Fatalf("failed to generate cert: %s", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}
	return &cert
}

func NewCertRequest(username string) *Msg {
	return &Msg{
		Type: MsgTypeCertRequest,
		Data: username,
	}
}

type CertResponse struct {
	Username    string `json:"username"`
	Certificate []byte `json:"certificate"`
}

func NewCertResponse(username string, certificate []byte) *Msg {
	return &Msg{
		Type: MsgTypeCertResponse,
		Data: &CertResponse{
			Username:    username,
			Certificate: certificate,
		},
	}
}
