package handler

import (
	"fmt"
	"net/http"

	"S-AES/models"
	"S-AES/utils"
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

func EncryptCBC(c *gin.Context) {
	var req models.EncryptCBCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	cipher, iv, err := saes.EncryptASCIIToBase64CBC(req.Plaintext, req.Key)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{
		"ciphertext": cipher,
		"iv":         iv,
	})
}

func DecryptCBC(c *gin.Context) {
	var req models.DecryptCBCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	plain, err := saes.DecryptBase64ToASCIICBC(req.Ciphertext, req.Key, req.IV)
	if err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}

	respondSuccess(c, gin.H{"plaintext": plain})
}

func MeetInTheMiddleAttack(c *gin.Context) {
	var req models.MeetInTheMiddleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, 1, err.Error())
		return
	}
	if len(req.Pairs) == 0 {
		respondError(c, http.StatusBadRequest, 1, "至少需要提供一组明文与密文")
		return
	}

	pairs := make([]utils.PlainCipherPair, 0, len(req.Pairs))
	for idx, pair := range req.Pairs {
		plain, err := utils.ParseBlockString(pair.Plaintext)
		if err != nil {
			respondError(c, http.StatusBadRequest, 1, fmt.Sprintf("第 %d 组明文解析失败: %v", idx+1, err))
			return
		}
		cipher, err := utils.ParseBlockString(pair.Ciphertext)
		if err != nil {
			respondError(c, http.StatusBadRequest, 1, fmt.Sprintf("第 %d 组密文解析失败: %v", idx+1, err))
			return
		}
		pairs = append(pairs, utils.PlainCipherPair{Plain: plain, Cipher: cipher})
	}

	keys, err := utils.MeetInTheMiddleAttack(pairs)
	if err != nil {
		respondError(c, http.StatusInternalServerError, 1, err.Error())
		return
	}

	respKeys := make([]models.MeetInTheMiddleKey, 0, len(keys))
	for _, key := range keys {
		respKeys = append(respKeys, models.MeetInTheMiddleKey{
			K1Hex:       utils.FormatHex16(key.K1),
			K1Bin:       utils.FormatBinary16(key.K1),
			K2Hex:       utils.FormatHex16(key.K2),
			K2Bin:       utils.FormatBinary16(key.K2),
			CombinedHex: utils.FormatCombinedHex(key.K1, key.K2),
			CombinedBin: utils.FormatCombinedBinary(key.K1, key.K2),
		})
	}

	respondSuccess(c, models.MeetInTheMiddleResponse{
		Count: len(respKeys),
		Keys:  respKeys,
	})
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
