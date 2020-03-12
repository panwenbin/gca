package actions

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/gin-gonic/gin"
	"github.com/panwenbin/gca/services/ca"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

var Serial int64

func init() {
	Serial, _ = strconv.ParseInt(time.Now().Format("20060102150405000"), 10, 64)
}

func SignWildcardDomain(c *gin.Context) {
	domain := c.Param("domain")
	ip := net.ParseIP(domain)
	atomic.AddInt64(&Serial, 1)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(Serial),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain, "*." + domain}
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	cert, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &priv.PublicKey, ca.KeyPair.PrivateKey)
	if err != nil {
		c.JSON(500, gin.H{
			"msg": "create cert error",
			"err": err.Error(),
		})
		return
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	c.JSON(200, gin.H{
		"cert": certPEM.String() + caPEM.String(),
		"key":  keyPEM.String(),
	})
	return
}
