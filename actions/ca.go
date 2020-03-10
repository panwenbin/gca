package actions

import (
	"bytes"
	"encoding/pem"
	"github.com/gin-gonic/gin"
	"github.com/panwenbin/gca/services/ca"
)

func Ca(c *gin.Context) {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Cert.Raw,
	})

	c.Header("Content-Disposition","attachment; filename=ca.crt")
	c.Header("Content-Type", "application/octet-stream")
	c.Writer.Write(certPEM.Bytes())

	return
}