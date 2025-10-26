package models

type EncryptRequest struct {
	Plaintext string `json:"plaintext" binding:"required"`
	Key       string `json:"key" binding:"required"`
}

type EncryptBase64Request struct {
	Plaintext string `json:"plaintext" binding:"required"`
	Key       string `json:"key" binding:"required"`
}

type DecryptRequest struct {
	Ciphertext string `json:"ciphertext" binding:"required"`
	Key        string `json:"key" binding:"required"`
}

type DecryptBase64Request struct {
	Ciphertext string `json:"ciphertext" binding:"required"`
	Key        string `json:"key" binding:"required"`
}

type AttackPair struct {
	Plaintext  string `json:"plaintext" binding:"required"`
	Ciphertext string `json:"ciphertext" binding:"required"`
}

type MeetInTheMiddleRequest struct {
	Pairs []AttackPair `json:"pairs" binding:"required"`
}
