package saes

// log-free核心实现，供性能场景（如中间相遇攻击）复用。

type roundKeyCore [4]byte
type state4 = [4]byte

func wordPairToRoundKeyCore(high, low byte) roundKeyCore {
	return roundKeyCore{
		(high >> 4) & 0x0F,
		high & 0x0F,
		(low >> 4) & 0x0F,
		low & 0x0F,
	}
}

func uint16ToStateCore(value uint16) state4 {
	return state4{
		byte((value >> 12) & 0x0F),
		byte((value >> 8) & 0x0F),
		byte((value >> 4) & 0x0F),
		byte(value & 0x0F),
	}
}

func addRoundKeyCore(state state4, roundKey roundKeyCore) state4 {
	for i := range state {
		state[i] ^= roundKey[i]
	}
	return state
}

func subNibCore(state state4, box [16]byte) state4 {
	for i, v := range state {
		state[i] = box[v&0x0F]
	}
	return state
}

func shiftRowsCore(state state4) state4 {
	state[1], state[3] = state[3], state[1]
	return state
}

func invShiftRowsCore(state state4) state4 {
	state[1], state[3] = state[3], state[1]
	return state
}

func mixColumnsCore(state state4) state4 {
	a, b := state[0], state[1]
	c, d := state[2], state[3]
	return state4{
		gfMulCore(0x1, a) ^ gfMulCore(0x4, b),
		gfMulCore(0x4, a) ^ gfMulCore(0x1, b),
		gfMulCore(0x1, c) ^ gfMulCore(0x4, d),
		gfMulCore(0x4, c) ^ gfMulCore(0x1, d),
	}
}

func invMixColumnsCore(state state4) state4 {
	a, b := state[0], state[1]
	c, d := state[2], state[3]
	return state4{
		gfMulCore(0x9, a) ^ gfMulCore(0x2, b),
		gfMulCore(0x2, a) ^ gfMulCore(0x9, b),
		gfMulCore(0x9, c) ^ gfMulCore(0x2, d),
		gfMulCore(0x2, c) ^ gfMulCore(0x9, d),
	}
}

func gfMulCore(a, b byte) byte {
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

func expandKeyCore(key uint16) [3]roundKeyCore {
	w0 := byte((key >> 8) & 0xFF)
	w1 := byte(key & 0xFF)

	w2 := w0 ^ g(w1, rCon[0])
	w3 := w2 ^ w1
	w4 := w2 ^ g(w3, rCon[1])
	w5 := w4 ^ w3

	return [3]roundKeyCore{
		wordPairToRoundKeyCore(w0, w1),
		wordPairToRoundKeyCore(w2, w3),
		wordPairToRoundKeyCore(w4, w5),
	}
}

func encryptBlockCore(block uint16, key uint16) uint16 {
	roundKeys := expandKeyCore(key)
	state := uint16ToStateCore(block)

	state = addRoundKeyCore(state, roundKeys[0])
	state = subNibCore(state, sBox)
	state = shiftRowsCore(state)
	state = mixColumnsCore(state)
	state = addRoundKeyCore(state, roundKeys[1])
	state = subNibCore(state, sBox)
	state = shiftRowsCore(state)
	state = addRoundKeyCore(state, roundKeys[2])

	return stateToUint16(state)
}

func decryptBlockCore(block uint16, key uint16) uint16 {
	roundKeys := expandKeyCore(key)
	state := uint16ToStateCore(block)

	state = addRoundKeyCore(state, roundKeys[2])
	state = invShiftRowsCore(state)
	state = subNibCore(state, invSBox)
	state = addRoundKeyCore(state, roundKeys[1])
	state = invMixColumnsCore(state)
	state = invShiftRowsCore(state)
	state = subNibCore(state, invSBox)
	state = addRoundKeyCore(state, roundKeys[0])

	return stateToUint16(state)
}

func doubleEncryptCore(block, k1, k2 uint16) uint16 {
	return encryptBlockCore(encryptBlockCore(block, k1), k2)
}

func tripleEncryptCore(block, k1, k2, k3 uint16) uint16 {
	return encryptBlockCore(encryptBlockCore(encryptBlockCore(block, k1), k2), k3)
}

func tripleDecryptCore(block, k1, k2, k3 uint16) uint16 {
	return decryptBlockCore(decryptBlockCore(decryptBlockCore(block, k3), k2), k1)
}

// 导出给其它包使用的无日志版本。

func EncryptBlockRaw(block, key uint16) uint16 {
	return encryptBlockCore(block, key)
}

func DecryptBlockRaw(block, key uint16) uint16 {
	return decryptBlockCore(block, key)
}

func DoubleEncryptRaw(block, k1, k2 uint16) uint16 {
	return doubleEncryptCore(block, k1, k2)
}

func TripleEncryptRaw(block, k1, k2, k3 uint16) uint16 {
	return tripleEncryptCore(block, k1, k2, k3)
}

func TripleDecryptRaw(block, k1, k2, k3 uint16) uint16 {
	return tripleDecryptCore(block, k1, k2, k3)
}
