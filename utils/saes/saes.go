package saes

import (
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

	k, err := parseBinary16(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	roundKeys := expandKey(k)
	state := uint16ToState(pt)

	state = addRoundKey(state, roundKeys[0])
	state = subNib(state, sBox)
	state = shiftRows(state)
	state = mixColumns(state)
	state = addRoundKey(state, roundKeys[1])
	state = subNib(state, sBox)
	state = shiftRows(state)
	state = addRoundKey(state, roundKeys[2])

	return fmt.Sprintf("%016b", stateToUint16(state)), nil
}

// DecryptBinary 接受16位（二进制字符串）密文与密钥，返回16位明文字符串。
func DecryptBinary(ciphertext, key string) (string, error) {
	ct, err := parseBinary16(ciphertext)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密文: %w", err)
	}

	k, err := parseBinary16(key)
	if err != nil {
		return "", fmt.Errorf("无法解析二进制密钥: %w", err)
	}

	roundKeys := expandKey(k)
	state := uint16ToState(ct)

	state = addRoundKey(state, roundKeys[2])
	state = invShiftRows(state)
	state = subNib(state, invSBox)
	state = addRoundKey(state, roundKeys[1])
	state = invMixColumns(state)
	state = invShiftRows(state)
	state = subNib(state, invSBox)
	state = addRoundKey(state, roundKeys[0])

	return fmt.Sprintf("%016b", stateToUint16(state)), nil
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

	return uint16(parsed), nil
}

func expandKey(key uint16) [3][4]byte {
	w := [6]byte{}
	w[0] = byte((key >> 8) & 0xFF)
	w[1] = byte(key & 0xFF)

	w[2] = w[0] ^ rCon[0] ^ g(w[1])
	w[3] = w[2] ^ w[1]
	w[4] = w[2] ^ rCon[1] ^ g(w[3])
	w[5] = w[4] ^ w[3]

	return [3][4]byte{
		wordPairToRoundKey(w[0], w[1]),
		wordPairToRoundKey(w[2], w[3]),
		wordPairToRoundKey(w[4], w[5]),
	}
}

func wordPairToRoundKey(high, low byte) [4]byte {
	return [4]byte{
		(high >> 4) & 0x0F,
		high & 0x0F,
		(low >> 4) & 0x0F,
		low & 0x0F,
	}
}

func g(word byte) byte {
	return subNibByte(rotNib(word))
}

func rotNib(word byte) byte {
	return ((word << 4) | (word >> 4)) & 0xFF
}

func subNibByte(word byte) byte {
	high := sBox[(word>>4)&0x0F]
	low := sBox[word&0x0F]
	return (high << 4) | low
}

func uint16ToState(value uint16) [4]byte {
	return [4]byte{
		byte((value >> 12) & 0x0F),
		byte((value >> 8) & 0x0F),
		byte((value >> 4) & 0x0F),
		byte(value & 0x0F),
	}
}

func stateToUint16(state [4]byte) uint16 {
	return (uint16(state[0]&0x0F) << 12) |
		(uint16(state[1]&0x0F) << 8) |
		(uint16(state[2]&0x0F) << 4) |
		uint16(state[3]&0x0F)
}

func addRoundKey(state [4]byte, roundKey [4]byte) [4]byte {
	for i := range state {
		state[i] ^= roundKey[i]
	}
	return state
}

func subNib(state [4]byte, box [16]byte) [4]byte {
	for i, v := range state {
		state[i] = box[v&0x0F]
	}
	return state
}

func shiftRows(state [4]byte) [4]byte {
	state[2], state[3] = state[3], state[2]
	return state
}

func invShiftRows(state [4]byte) [4]byte {
	// 对2x2矩阵而言，左移和右移效果相同，依然交换即可
	return shiftRows(state)
}

func mixColumns(state [4]byte) [4]byte {
	a, b, c, d := state[0], state[1], state[2], state[3]
	return [4]byte{
		gfMul(0x1, a) ^ gfMul(0x4, c),
		gfMul(0x1, b) ^ gfMul(0x4, d),
		gfMul(0x4, a) ^ gfMul(0x1, c),
		gfMul(0x4, b) ^ gfMul(0x1, d),
	}
}

func invMixColumns(state [4]byte) [4]byte {
	a, b, c, d := state[0], state[1], state[2], state[3]
	return [4]byte{
		gfMul(0x9, a) ^ gfMul(0x2, c),
		gfMul(0x9, b) ^ gfMul(0x2, d),
		gfMul(0x2, a) ^ gfMul(0x9, c),
		gfMul(0x2, b) ^ gfMul(0x9, d),
	}
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

	return res & 0x0F
}
