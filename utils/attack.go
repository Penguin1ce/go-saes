package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"S-AES/utils/saes"
)

// PlainCipherPair 记录一组明文与密文（16-bit）用于中间相遇攻击。
type PlainCipherPair struct {
	Plain  uint16
	Cipher uint16
}

// KeyPair 表示候选的 (K1, K2) 组合。
type KeyPair struct {
	K1 uint16
	K2 uint16
}

// ParseBlockString 将 16-bit 二进制或十六进制字符串解析为 uint16。
func ParseBlockString(input string) (uint16, error) {
	sanitized := sanitizeBlockString(input)
	if sanitized == "" {
		return 0, fmt.Errorf("输入不能为空")
	}

	lower := strings.ToLower(sanitized)
	if strings.HasPrefix(lower, "0x") {
		hexPart := sanitized[2:]
		if len(hexPart) != 4 {
			return 0, fmt.Errorf("十六进制输入必须是 4 个字符")
		}
		value, err := strconv.ParseUint(hexPart, 16, 16)
		if err != nil {
			return 0, fmt.Errorf("无法解析十六进制字符串: %w", err)
		}
		return uint16(value), nil
	}

	if len(sanitized) != 16 {
		return 0, fmt.Errorf("二进制输入必须是 16 位")
	}
	for _, ch := range sanitized {
		if ch != '0' && ch != '1' {
			return 0, fmt.Errorf("仅支持二进制字符 0 或 1")
		}
	}

	value, err := strconv.ParseUint(sanitized, 2, 16)
	if err != nil {
		return 0, fmt.Errorf("无法解析二进制字符串: %w", err)
	}
	return uint16(value), nil
}

// MeetInTheMiddleAttack 执行中间相遇攻击，返回所有匹配的 (K1, K2) 组合。
func MeetInTheMiddleAttack(pairs []PlainCipherPair) ([]KeyPair, error) {
	if len(pairs) == 0 {
		return nil, fmt.Errorf("至少需要一个明文/密文对")
	}

	forwardMap := make(map[uint16][]uint16, 1<<16)
	first := pairs[0]

	for k1 := 0; k1 <= 0xFFFF; k1++ {
		mid := saes.EncryptBlockRaw(first.Plain, uint16(k1))
		forwardMap[mid] = append(forwardMap[mid], uint16(k1))
	}

	candidates := make(map[KeyPair]struct{})
	for k2 := 0; k2 <= 0xFFFF; k2++ {
		mid := saes.DecryptBlockRaw(first.Cipher, uint16(k2))
		possible, ok := forwardMap[mid]
		if !ok {
			continue
		}
		for _, k1 := range possible {
			pair := KeyPair{K1: k1, K2: uint16(k2)}
			if verifyCandidate(pair, pairs) {
				candidates[pair] = struct{}{}
			}
		}
	}

	results := make([]KeyPair, 0, len(candidates))
	for pair := range candidates {
		results = append(results, pair)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].K1 == results[j].K1 {
			return results[i].K2 < results[j].K2
		}
		return results[i].K1 < results[j].K1
	})

	return results, nil
}

func verifyCandidate(pair KeyPair, pairs []PlainCipherPair) bool {
	for _, pc := range pairs {
		if saes.DoubleEncryptRaw(pc.Plain, pair.K1, pair.K2) != pc.Cipher {
			return false
		}
	}
	return true
}

func sanitizeBlockString(input string) string {
	return strings.ReplaceAll(strings.TrimSpace(input), " ", "")
}

// FormatBinary16 以 16 位二进制字符串表示数值。
func FormatBinary16(value uint16) string {
	return fmt.Sprintf("%016b", value)
}

// FormatHex16 以 0x 前缀的 4 位十六进制字符串表示数值。
func FormatHex16(value uint16) string {
	return fmt.Sprintf("0x%04X", value)
}

// FormatCombinedHex 拼接 (K1||K2) 为 32 位十六进制字符串。
func FormatCombinedHex(k1, k2 uint16) string {
	return fmt.Sprintf("0x%04X%04X", k1, k2)
}

// FormatCombinedBinary 拼接 (K1||K2) 为 32 位二进制字符串。
func FormatCombinedBinary(k1, k2 uint16) string {
	return fmt.Sprintf("%s%s", FormatBinary16(k1), FormatBinary16(k2))
}
