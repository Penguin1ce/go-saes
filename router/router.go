package router

import (
	"S-AES/handler"
	"S-AES/middleware"

	"github.com/gin-gonic/gin"
)

func InitRouter(r *gin.Engine) {
	r.Use(gin.Recovery(), middleware.Cors())
	r.POST("/encrypt", handler.Encrypt)
	r.POST("/decrypt", handler.Decrypt)
}
