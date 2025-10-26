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
	r.POST("/encrypt/base64", handler.EncryptBase64)
	r.POST("/decrypt/base64", handler.DecryptBase64)
	r.POST("/encrypt/cbc", handler.EncryptCBC)
	r.POST("/decrypt/cbc", handler.DecryptCBC)
	r.POST("/attack/meet-in-the-middle", handler.MeetInTheMiddleAttack)
}
