package saes

import (
	"encoding/base64"
	"fmt"
	"log"
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
	log.Printf("EncryptBinary: 输入明文=%s, 密钥=%s", plaintext, key)

	pt, err := parseBinary16(plaintext)
	if err != nil {
		log.Printf("EncryptBinary: 解析明文失败: %v", err)
		return "", fmt.Errorf("无法解析二进制明文: %w", err)
	}

	sanitizedKey, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		log.Printf("EncryptBinary: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	var block uint16
	if isDouble {
		log.Printf("EncryptBinary: 使用 32 位密钥 %s (K1=0x%04X, K2=0x%04X)", sanitizedKey, k1, k2)
		block = doubleEncrypt(pt, k1, k2, "EncryptBinary")
	} else {
		log.Printf("EncryptBinary: 使用 16 位密钥 %s", sanitizedKey)
		block = encryptBlock(pt, k1, "EncryptBinary")
	}
	result := fmt.Sprintf("%016b", block)
	log.Printf("EncryptBinary: 输出密文=%s", result)
	return result, nil
}

// DecryptBinary 接受16位（二进制字符串）密文与密钥，返回16位明文字符串。
func DecryptBinary(ciphertext, key string) (string, error) {
	log.Printf("DecryptBinary: 输入密文=%s, 密钥=%s", ciphertext, key)

	ct, err := parseBinary16(ciphertext)
	if err != nil {
		log.Printf("DecryptBinary: 解析密文失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密文: %w", err)
	}

	sanitizedKey, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		log.Printf("DecryptBinary: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	var block uint16
	if isDouble {
		log.Printf("DecryptBinary: 使用 32 位密钥 %s (K1=0x%04X, K2=0x%04X)", sanitizedKey, k1, k2)
		block = doubleDecrypt(ct, k1, k2, "DecryptBinary")
	} else {
		log.Printf("DecryptBinary: 使用 16 位密钥 %s", sanitizedKey)
		block = decryptBlock(ct, k1, "DecryptBinary")
	}
	result := fmt.Sprintf("%016b", block)
	log.Printf("DecryptBinary: 输出明文=%s", result)
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
	value, sanitized, err := parseBinary(input, 16)
	if err != nil {
		return 0, err
	}

	res := uint16(value)
	log.Printf("parseBinary16: 输入=%s, 输出=0x%04X", sanitized, res)
	return res, nil
}

func parseKey(key string) (string, uint16, uint16, bool, error) {
	sanitized := sanitizeBinaryString(key)
	switch len(sanitized) {
	case 16:
		k1, err := parseBinary16(sanitized)
		if err != nil {
			return "", 0, 0, false, err
		}
		log.Printf("parseKey: 输入=%s, 模式=单轮, K=0x%04X", sanitized, k1)
		return sanitized, k1, 0, false, nil
	case 32:
		value, _, err := parseBinary(sanitized, 32)
		if err != nil {
			return "", 0, 0, false, err
		}
		k1 := uint16(value >> 16)
		k2 := uint16(value & 0xFFFF)
		log.Printf("parseKey: 输入=%s, 模式=双重, K1=0x%04X, K2=0x%04X", sanitized, k1, k2)
		return sanitized, k1, k2, true, nil
	default:
		return "", 0, 0, false, fmt.Errorf("密钥必须是16位或32位二进制字符串")
	}
}

func doubleEncrypt(block uint16, k1, k2 uint16, prefix string) uint16 {
	first := encryptBlock(block, k1, prefix+" 第一次加密")
	return encryptBlock(first, k2, prefix+" 第二次加密")
}

func doubleDecrypt(block uint16, k1, k2 uint16, prefix string) uint16 {
	first := decryptBlock(block, k2, prefix+" 第一次解密")
	return decryptBlock(first, k1, prefix+" 第二次解密")
}

func encryptBlock(block uint16, key uint16, prefix string) uint16 {
	roundKeys := expandKey(key)
	log.Printf("%s: 输入分组=0x%04X, 子密钥=0x%04X", prefix, block, key)
	log.Printf("%s: 轮密钥=%v", prefix, roundKeys)

	state := uint16ToState(block)
	logState(fmt.Sprintf("%s: 初始状态", prefix), state)

	state = addRoundKey(state, roundKeys[0])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K0)", prefix), state)

	state = subNib(state, sBox)
	logState(fmt.Sprintf("%s: 执行 subNib→Sbox", prefix), state)

	state = shiftRows(state)
	logState(fmt.Sprintf("%s: 执行 shiftRows", prefix), state)

	state = mixColumns(state)
	logState(fmt.Sprintf("%s: 执行 mixColumns", prefix), state)

	state = addRoundKey(state, roundKeys[1])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K1)", prefix), state)

	state = subNib(state, sBox)
	logState(fmt.Sprintf("%s: 执行第二轮 subNib→Sbox", prefix), state)

	state = shiftRows(state)
	logState(fmt.Sprintf("%s: 执行第二轮 shiftRows", prefix), state)

	state = addRoundKey(state, roundKeys[2])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K2)", prefix), state)

	result := stateToUint16(state)
	log.Printf("%s: 输出分组=0x%04X", prefix, result)
	return result
}

func decryptBlock(block uint16, key uint16, prefix string) uint16 {
	roundKeys := expandKey(key)
	log.Printf("%s: 输入分组=0x%04X, 子密钥=0x%04X", prefix, block, key)
	log.Printf("%s: 轮密钥=%v", prefix, roundKeys)

	state := uint16ToState(block)
	logState(fmt.Sprintf("%s: 初始状态", prefix), state)

	state = addRoundKey(state, roundKeys[2])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K2)", prefix), state)

	state = invShiftRows(state)
	logState(fmt.Sprintf("%s: 执行首次 invShiftRows", prefix), state)

	state = subNib(state, invSBox)
	logState(fmt.Sprintf("%s: 执行首次 subNib→invSBox", prefix), state)

	state = addRoundKey(state, roundKeys[1])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K1)", prefix), state)

	state = invMixColumns(state)
	logState(fmt.Sprintf("%s: 执行 invMixColumns", prefix), state)

	state = invShiftRows(state)
	logState(fmt.Sprintf("%s: 执行第二次 invShiftRows", prefix), state)

	state = subNib(state, invSBox)
	logState(fmt.Sprintf("%s: 执行第二次 subNib→invSBox", prefix), state)

	state = addRoundKey(state, roundKeys[0])
	logState(fmt.Sprintf("%s: 执行 addRoundKey(K0)", prefix), state)

	result := stateToUint16(state)
	log.Printf("%s: 输出分组=0x%04X", prefix, result)
	return result
}

func wordPairToRoundKey(high, low byte) [4]byte {
	result := [4]byte{
		(high >> 4) & 0x0F,
		high & 0x0F,
		(low >> 4) & 0x0F,
		low & 0x0F,
	}
	log.Printf("wordPairToRoundKey: 输入=(0x%02X,0x%02X), 输出=%v", high, low, result)
	return result
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
	result := [4]byte{
		byte((value >> 12) & 0x0F),
		byte((value >> 8) & 0x0F),
		byte((value >> 4) & 0x0F),
		byte(value & 0x0F),
	}
	log.Printf("uint16ToState: 输入=0x%04X, 输出=%v", value, result)
	return result
}

func stateToUint16(state [4]byte) uint16 {
	return (uint16(state[0]) << 12) |
		(uint16(state[1]) << 8) |
		(uint16(state[2]) << 4) |
		uint16(state[3])
}

func addRoundKey(state [4]byte, roundKey [4]byte) [4]byte {
	original := state
	for i := range state {
		state[i] ^= roundKey[i]
	}
	log.Printf("addRoundKey: 输入状态=%v, 轮密钥=%v, 输出状态=%v", original, roundKey, state)
	return state
}

func subNib(state [4]byte, box [16]byte) [4]byte {
	original := state
	for i, v := range state {
		state[i] = box[v&0x0F]
	}
	log.Printf("subNib: 输入状态=%v, 输出状态=%v", original, state)
	return state
}

func shiftRows(state [4]byte) [4]byte {
	original := state
	state[2], state[3] = state[3], state[2]
	log.Printf("shiftRows: 输入状态=%v, 输出状态=%v", original, state)
	return state
}

func invShiftRows(state [4]byte) [4]byte {
	original := state
	state[2], state[3] = state[3], state[2]
	log.Printf("invShiftRows: 输入状态=%v, 输出状态=%v", original, state)
	return state
}

func mixColumns(state [4]byte) [4]byte {
	a, c := state[0], state[2]
	b, d := state[1], state[3]
	result := [4]byte{
		gfMul(0x1, a) ^ gfMul(0x4, c),
		gfMul(0x1, b) ^ gfMul(0x4, d),
		gfMul(0x4, a) ^ gfMul(0x1, c),
		gfMul(0x4, b) ^ gfMul(0x1, d),
	}
	log.Printf("mixColumns: 输入状态=%v, 输出状态=%v", state, result)
	return result
}

func invMixColumns(state [4]byte) [4]byte {
	a, c := state[0], state[2]
	b, d := state[1], state[3]
	result := [4]byte{
		gfMul(0x9, a) ^ gfMul(0x2, c),
		gfMul(0x9, b) ^ gfMul(0x2, d),
		gfMul(0x2, a) ^ gfMul(0x9, c),
		gfMul(0x2, b) ^ gfMul(0x9, d),
	}
	log.Printf("invMixColumns: 输入状态=%v, 输出状态=%v", state, result)
	return result
}

func gfMul(a, b byte) byte {
	var res byte
	x := a & 0x0F
	y := b & 0x0F

	for i := 0; i < 4; i++ {
		if (y & 0x1) != 0 {
			res ^= x
		}

		overflow := (x & 0x8) != 0
		x = (x << 1) & 0x0F
		if overflow {
			x ^= 0x3
		}

		y >>= 1
	}

	final := res & 0x0F
	log.Printf("gfMul: 乘数=%d, 被乘数=%d, 结果=0x%X", a&0x0F, b&0x0F, final)
	return final
}

func logState(label string, state [4]byte) {
	log.Printf("%s -> 状态=%v (0x%04X)", label, state, stateToUint16(state))
}

// EncryptASCIIToBase64 将 ASCII 明文（按 2 字节分组）转换为 Base64 编码的密文。
func EncryptASCIIToBase64(plaintext, key string) (string, error) {
	log.Printf("EncryptASCIIToBase64: 输入明文=%q, 密钥=%s", plaintext, key)

	if len(plaintext) == 0 {
		return "", fmt.Errorf("明文不能为空")
	}
	for _, r := range plaintext {
		if r > 0x7F {
			return "", fmt.Errorf("检测到非 ASCII 字符: %q", r)
		}
	}

	sanitizedKey, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		log.Printf("EncryptASCIIToBase64: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}
	if isDouble {
		log.Printf("EncryptASCIIToBase64: 使用 32 位密钥 %s (K1=0x%04X, K2=0x%04X)", sanitizedKey, k1, k2)
	} else {
		log.Printf("EncryptASCIIToBase64: 使用 16 位密钥 %s", sanitizedKey)
	}

	rawBytes := []byte(plaintext)
	needsPadding := len(rawBytes)%2 != 0
	if needsPadding {
		rawBytes = append(rawBytes, 0x00)
		log.Printf("EncryptASCIIToBase64: 明文长度为奇数，已自动补齐 0x00")
	}

	cipherBytes := make([]byte, 0, len(rawBytes))

	for i := 0; i < len(rawBytes); i += 2 {
		high := rawBytes[i]
		low := rawBytes[i+1]
		block := (uint16(high) << 8) | uint16(low)
		label := fmt.Sprintf("EncryptASCIIToBase64: 分组 %d", (i/2)+1)
		var enc uint16
		if isDouble {
			enc = doubleEncrypt(block, k1, k2, label)
		} else {
			enc = encryptBlock(block, k1, label)
		}
		cipherBytes = append(cipherBytes, byte(enc>>8), byte(enc&0xFF))
	}

	encoded := base64.StdEncoding.EncodeToString(cipherBytes)
	log.Printf("EncryptASCIIToBase64: 输出 Base64 密文=%s", encoded)
	return encoded, nil
}

// DecryptBase64ToASCII 将 Base64 编码的密文解密为 ASCII 明文。
func DecryptBase64ToASCII(ciphertext, key string) (string, error) {
	log.Printf("DecryptBase64ToASCII: 输入密文=%s, 密钥=%s", ciphertext, key)

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

	sanitizedKey, k1, k2, isDouble, err := parseKey(key)
	if err != nil {
		log.Printf("DecryptBase64ToASCII: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}
	if isDouble {
		log.Printf("DecryptBase64ToASCII: 使用 32 位密钥 %s (K1=0x%04X, K2=0x%04X)", sanitizedKey, k1, k2)
	} else {
		log.Printf("DecryptBase64ToASCII: 使用 16 位密钥 %s", sanitizedKey)
	}

	resultBytes := make([]byte, 0, len(cipherBytes))

	for i := 0; i < len(cipherBytes); i += 2 {
		high := cipherBytes[i]
		low := cipherBytes[i+1]
		block := (uint16(high) << 8) | uint16(low)
		label := fmt.Sprintf("DecryptBase64ToASCII: 分组 %d", (i/2)+1)
		var dec uint16
		if isDouble {
			dec = doubleDecrypt(block, k1, k2, label)
		} else {
			dec = decryptBlock(block, k1, label)
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

	log.Printf("DecryptBase64ToASCII: 输出明文=%q", result)
	return result, nil
}
