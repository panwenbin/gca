package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

var KeyPair tls.Certificate
var Cert *x509.Certificate

const (
    DEFAULT_CA_CRT = "ca.crt"
    DEFAULT_CA_KEY = "ca.key"
)

func init() {
	caCert := os.Getenv("CA_CERT")
	if caCert == "" {
		caCert = DEFAULT_CA_CRT
	}

	caKey := os.Getenv("CA_KEY")
	if caKey == "" {
		caKey = DEFAULT_CA_KEY
	}

	var err error
	KeyPair, err = tls.LoadX509KeyPair(caCert, caKey)
	if err != nil {
		log.Println("load ca failed, try generate")
		caPEM, caPrivKeyPEM, err := GenerateCa()
		if err != nil {
			log.Fatalln(err)
		}
		err = ioutil.WriteFile(DEFAULT_CA_CRT, caPEM.Bytes(), 0644)
		if err != nil {
			log.Fatalln(err)
		}
		err = ioutil.WriteFile(DEFAULT_CA_KEY, caPrivKeyPEM.Bytes(), 0600)
		if err != nil {
			log.Fatalln(err)
		}
		KeyPair, err = tls.X509KeyPair(caPEM.Bytes(), caPrivKeyPEM.Bytes())
	}
	Cert, err = x509.ParseCertificate(KeyPair.Certificate[0])
	if err != nil {
		log.Fatalln(err)
	}

	Cert, err = x509.ParseCertificate(KeyPair.Certificate[0])
	if err != nil {
		log.Fatalln(err)
	}
}

func GenerateCa() (caPEM, caPrivKeyPEM *bytes.Buffer, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			CommonName: "gCA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM = new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return
}
