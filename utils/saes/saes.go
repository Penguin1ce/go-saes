package saes

import (
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

	k, err := parseBinary16(key)
	if err != nil {
		log.Printf("EncryptBinary: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	roundKeys := expandKey(k)
	state := uint16ToState(pt)
	log.Printf("EncryptBinary: 轮密钥=%v", roundKeys)
	logState("EncryptBinary: 初始状态", state)

	state = addRoundKey(state, roundKeys[0])
	logState("EncryptBinary: 执行 addRoundKey(K0)", state)

	state = subNib(state, sBox)
	logState("EncryptBinary: 执行 subNib→Sbox", state)

	state = shiftRows(state)
	logState("EncryptBinary: 执行 shiftRows", state)

	state = mixColumns(state)
	logState("EncryptBinary: 执行 mixColumns", state)

	state = addRoundKey(state, roundKeys[1])
	logState("EncryptBinary: 执行 addRoundKey(K1)", state)

	state = subNib(state, sBox)
	logState("EncryptBinary: 第二轮 subNib→Sbox", state)

	state = shiftRows(state)
	logState("EncryptBinary: 第二轮 shiftRows", state)

	state = addRoundKey(state, roundKeys[2])
	logState("EncryptBinary: 执行 addRoundKey(K2)", state)

	result := fmt.Sprintf("%016b", stateToUint16(state))
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

	k, err := parseBinary16(key)
	if err != nil {
		log.Printf("DecryptBinary: 解析密钥失败: %v", err)
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	roundKeys := expandKey(k)
	state := uint16ToState(ct)
	log.Printf("DecryptBinary: 轮密钥=%v", roundKeys)
	logState("DecryptBinary: 初始状态", state)

	state = addRoundKey(state, roundKeys[2])
	logState("DecryptBinary: 执行 addRoundKey(K2)", state)

	state = invShiftRows(state)
	logState("DecryptBinary: 执行 invShiftRows 第一次", state)

	state = subNib(state, invSBox)
	logState("DecryptBinary: 执行 subNib→invSBox 第一次", state)

	state = addRoundKey(state, roundKeys[1])
	logState("DecryptBinary: 执行 addRoundKey(K1)", state)

	state = invMixColumns(state)
	logState("DecryptBinary: 执行 invMixColumns", state)

	state = invShiftRows(state)
	logState("DecryptBinary: 执行 invShiftRows 第二次", state)

	state = subNib(state, invSBox)
	logState("DecryptBinary: 执行 subNib→invSBox 第二次", state)

	state = addRoundKey(state, roundKeys[0])
	logState("DecryptBinary: 执行 addRoundKey(K0)", state)

	result := fmt.Sprintf("%016b", stateToUint16(state))
	log.Printf("DecryptBinary: 输出明文=%s", result)
	return result, nil
}

func parseBinary16(input string) (uint16, error) {
	value := strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if len(value) != 16 {
		return 0, fmt.Errorf("输入必须是16位二进制字符串")
	}

	for _, ch := range value {
		if ch != '0' && ch != '1' {
			return 0, fmt.Errorf("仅支持字符0或1")
		}
	}

	parsed, err := strconv.ParseUint(value, 2, 16)
	if err != nil {
		return 0, err
	}

	res := uint16(parsed)
	log.Printf("parseBinary16: 输入=%s, 输出=0x%04X", input, res)
	return res, nil
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

func g(word, rcon byte) byte {
	a := (word >> 4) & 0x0F
	b := word & 0x0F
	out := (sBox[a] << 4) | sBox[b]
	return out ^ rcon
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
