package handler

import (
	"net/http"

	"S-AES/models"
	"S-AES/utils/saes"

	"github.com/gin-gonic/gin"
)

func Encrypt(c *gin.Context) {
	var req models.EncryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	cipher, err := saes.EncryptBinary(req.Plaintext, req.Key)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{"ciphertext": cipher})
}

func Decrypt(c *gin.Context) {
	var req models.DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	plain, err := saes.DecryptBinary(req.Ciphertext, req.Key)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{"plaintext": plain})
}

func EncryptBase64(c *gin.Context) {
	var req models.EncryptBase64Request
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	cipher, err := saes.EncryptASCIIToBase64(req.Plaintext, req.Key)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{"ciphertext": cipher})
}

func DecryptBase64(c *gin.Context) {
	var req models.DecryptBase64Request
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	plain, err := saes.DecryptBase64ToASCII(req.Ciphertext, req.Key)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{"plaintext": plain})
}

func respondSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, models.APIResponse{
		Code:    0,
		Message: "success",
		Data:    data,
	})
}

func respondError(c *gin.Context, status, code int, message string) {
	c.JSON(status, models.APIResponse{
		Code:    code,
		Message: message,
	})
}
