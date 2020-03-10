package main

import (
	"github.com/gin-gonic/gin"
	"github.com/panwenbin/gca/actions"
)

func main() {
	r := gin.Default()
	r.GET("/ca", actions.Ca)
	r.GET("/sign/:domain", actions.SignWildcardDomain)
	r.Run()
}
