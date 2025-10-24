package main

import (
	"S-AES/router"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	router.InitRouter(r)
	if err := r.Run("localhost:8080"); err != nil {
		panic(err)
	}
	log.Println("Server running on localhost:8080")
}
