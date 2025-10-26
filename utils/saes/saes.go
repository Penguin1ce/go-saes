package saes

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

var (
	sBox    = [16]byte{0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7}
	invSBox = [16]byte{0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE}
	rCon    = [2]byte{0x80, 0x30}
)

// EncryptBinary 接受16位（二进制字符串）明文与密钥，返回16位密文字符串。
func EncryptBinary(plaintext, key string) (string, error) {
	pt, err := parseBinary16(plaintext)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制明文: %w", err)
	}

	_, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	var block uint16
	if isDouble {
		block = doubleEncrypt(pt, k1, k2)
	} else {
		block = encryptBlock(pt, k1)
	}
	result := fmt.Sprintf("%016b", block)
	return result, nil
}

// DecryptBinary 接受16位（二进制字符串）密文与密钥，返回16位明文字符串。
func DecryptBinary(ciphertext, key string) (string, error) {
	ct, err := parseBinary16(ciphertext)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密文: %w", err)
	}

	_, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	var block uint16
	if isDouble {
		block = doubleDecrypt(ct, k1, k2)
	} else {
		block = decryptBlock(ct, k1)
	}
	result := fmt.Sprintf("%016b", block)
	return result, nil
}

func sanitizeBinaryString(input string) string {
	return strings.ReplaceAll(strings.TrimSpace(input), " ", "")
}

func parseBinary(input string, bits int) (uint64, string, error) {
	sanitized := sanitizeBinaryString(input)
	if len(sanitized) != bits {
		return 0, "", fmt.Errorf("输入必须是%d位二进制字符串", bits)
	}

	for _, ch := range sanitized {
		if ch != '0' && ch != '1' {
			return 0, "", fmt.Errorf("仅支持字符0或1")
		}
	}

	parsed, err := strconv.ParseUint(sanitized, 2, bits)
	if err != nil {
		return 0, "", err
	}

	return parsed, sanitized, nil
}

func parseBinary16(input string) (uint16, error) {
	value := sanitizeBinaryString(input)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "0x") {
		hexPart := value[2:]
		if len(hexPart) != 4 {
			return 0, fmt.Errorf("十六进制输入必须包含 4 个十六进制字符")
		}
		parsed, err := strconv.ParseUint(hexPart, 16, 16)
		if err != nil {
			return 0, fmt.Errorf("无法解析十六进制输入: %w", err)
		}
		res := uint16(parsed)
		return res, nil
	}

	parsed, _, err := parseBinary(value, 16)
	if err != nil {
		return 0, err
	}

	res := uint16(parsed)
	return res, nil
}

func parseKey(key string) (string, uint16, uint16, bool, error) {
	sanitized := sanitizeBinaryString(key)
	if sanitized == "" {
		return "", 0, 0, false, fmt.Errorf("密钥不能为空")
	}

	lower := strings.ToLower(sanitized)
	if strings.HasPrefix(lower, "0x") {
		hexPart := sanitized[2:]
		switch len(hexPart) {
		case 4:
			parsed, err := strconv.ParseUint(hexPart, 16, 16)
			if err != nil {
				return "", 0, 0, false, fmt.Errorf("无法解析十六进制密钥: %w", err)
			}
			k1 := uint16(parsed)
			formatted := "0x" + strings.ToUpper(hexPart)
			return formatted, k1, 0, false, nil
		case 8:
			parsed, err := strconv.ParseUint(hexPart, 16, 32)
			if err != nil {
				return "", 0, 0, false, fmt.Errorf("无法解析十六进制密钥: %w", err)
			}
			k1 := uint16(parsed >> 16)
			k2 := uint16(parsed & 0xFFFF)
			formatted := "0x" + strings.ToUpper(hexPart)
			return formatted, k1, k2, true, nil
		default:
			return "", 0, 0, false, fmt.Errorf("十六进制密钥长度必须为 4 或 8 个字符")
		}
	}

	switch len(sanitized) {
	case 16:
		k1, err := parseBinary16(sanitized)
		if err != nil {
			return "", 0, 0, false, err
		}
		return sanitized, k1, 0, false, nil
	case 32:
		parsed, binary, err := parseBinary(sanitized, 32)
		if err != nil {
			return "", 0, 0, false, err
		}
		k1 := uint16(parsed >> 16)
		k2 := uint16(parsed & 0xFFFF)
		return binary, k1, k2, true, nil
	default:
		return "", 0, 0, false, fmt.Errorf("密钥必须是16位或32位二进制字符串，或对应长度的十六进制字符串（可带0x前缀）")
	}
}

func doubleEncrypt(block uint16, k1, k2 uint16) uint16 {
	first := encryptBlock(block, k1)
	return encryptBlock(first, k2)
}

func doubleDecrypt(block uint16, k1, k2 uint16) uint16 {
	first := decryptBlock(block, k2)
	return decryptBlock(first, k1)
}

func encryptBlock(block uint16, key uint16) uint16 {
	roundKeys := expandKey(key)
	state := uint16ToState(block)

	state = addRoundKey(state, roundKeys[0])
	state = subNib(state, sBox)
	state = shiftRows(state)
	state = mixColumns(state)
	state = addRoundKey(state, roundKeys[1])
	state = subNib(state, sBox)
	state = shiftRows(state)
	state = addRoundKey(state, roundKeys[2])

	return stateToUint16(state)
}

func decryptBlock(block uint16, key uint16) uint16 {
	roundKeys := expandKey(key)
	state := uint16ToState(block)

	state = addRoundKey(state, roundKeys[2])
	state = invShiftRows(state)
	state = subNib(state, invSBox)
	state = addRoundKey(state, roundKeys[1])
	state = invMixColumns(state)
	state = invShiftRows(state)
	state = subNib(state, invSBox)
	state = addRoundKey(state, roundKeys[0])

	return stateToUint16(state)
}

func wordPairToRoundKey(high, low byte) [4]byte {
	return wordPairToRoundKeyCore(high, low)
}

func rotNib(w byte) byte {
	return ((w << 4) | (w >> 4)) & 0xFF
}

func g(word, rcon byte) byte {
	w := rotNib(word) // ① 先 RotNib（教材要求）
	a := (w >> 4) & 0x0F
	b := w & 0x0F
	out := (sBox[a] << 4) | sBox[b] // ② 再 SubNib
	return out ^ rcon               // ③ 最后 XOR Rcon
}

func expandKey(key uint16) [3][4]byte {
	w0 := byte((key >> 8) & 0xFF)
	w1 := byte(key & 0xFF)

	w2 := w0 ^ g(w1, rCon[0])
	w3 := w2 ^ w1
	w4 := w2 ^ g(w3, rCon[1])
	w5 := w4 ^ w3

	return [3][4]byte{
		wordPairToRoundKey(w0, w1),
		wordPairToRoundKey(w2, w3),
		wordPairToRoundKey(w4, w5),
	}
}

func uint16ToState(value uint16) [4]byte {
	return uint16ToStateCore(value)
}

func stateToUint16(state [4]byte) uint16 {
	return (uint16(state[0]) << 12) |
		(uint16(state[1]) << 8) |
		(uint16(state[2]) << 4) |
		uint16(state[3])
}

func addRoundKey(state [4]byte, roundKey [4]byte) [4]byte {
	return addRoundKeyCore(state, roundKey)
}

func subNib(state [4]byte, box [16]byte) [4]byte {
	return subNibCore(state, box)
}

func shiftRows(state [4]byte) [4]byte {
	return shiftRowsCore(state)
}

func invShiftRows(state [4]byte) [4]byte {
	return invShiftRowsCore(state)
}

func mixColumns(state [4]byte) [4]byte {
	return mixColumnsCore(state)
}

func invMixColumns(state [4]byte) [4]byte {
	return invMixColumnsCore(state)
}

func gfMul(a, b byte) byte {
	return gfMulCore(a, b)
}

// EncryptASCIIToBase64 将 ASCII 明文（按 2 字节分组）转换为 Base64 编码的密文。
func EncryptASCIIToBase64(plaintext, key string) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("明文不能为空")
	}
	for _, r := range plaintext {
		if r > 0x7F {
			return "", fmt.Errorf("检测到非 ASCII 字符: %q", r)
		}
	}

	_, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	rawBytes := []byte(plaintext)
	needsPadding := len(rawBytes)%2 != 0
	if needsPadding {
		rawBytes = append(rawBytes, 0x00)
	}

	cipherBytes := make([]byte, 0, len(rawBytes))

	for i := 0; i < len(rawBytes); i += 2 {
		high := rawBytes[i]
		low := rawBytes[i+1]
		block := (uint16(high) << 8) | uint16(low)
		var enc uint16
		if isDouble {
			enc = doubleEncrypt(block, k1, k2)
		} else {
			enc = encryptBlock(block, k1)
		}
		cipherBytes = append(cipherBytes, byte(enc>>8), byte(enc&0xFF))
	}

	encoded := base64.StdEncoding.EncodeToString(cipherBytes)
	return encoded, nil
}

// DecryptBase64ToASCII 将 Base64 编码的密文解密为 ASCII 明文。
func DecryptBase64ToASCII(ciphertext, key string) (string, error) {
	sanitizedCipher := strings.TrimSpace(ciphertext)
	if sanitizedCipher == "" {
		return "", fmt.Errorf("密文不能为空")
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(sanitizedCipher)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}
	if len(cipherBytes)%2 != 0 {
		return "", fmt.Errorf("密文字节长度必须是 2 的倍数")
	}

	_, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	resultBytes := make([]byte, 0, len(cipherBytes))

	for i := 0; i < len(cipherBytes); i += 2 {
		high := cipherBytes[i]
		low := cipherBytes[i+1]
		block := (uint16(high) << 8) | uint16(low)
		var dec uint16
		if isDouble {
			dec = doubleDecrypt(block, k1, k2)
		} else {
			dec = decryptBlock(block, k1)
		}
		resultBytes = append(resultBytes, byte(dec>>8), byte(dec&0xFF))
	}

	// 去除可能的补位 0x00（仅用于保持 16 bit 分组）
	if len(resultBytes) > 0 && resultBytes[len(resultBytes)-1] == 0x00 {
		resultBytes = resultBytes[:len(resultBytes)-1]
	}

	result := string(resultBytes)
	for _, r := range result {
		if r > 0x7F {
			return "", fmt.Errorf("解密结果包含非 ASCII 字符: %q", r)
		}
	}

	return result, nil
}
