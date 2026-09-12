package common

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"path/filepath"
	"strings"
)

// SecureRandInt 使用 crypto/rand 生成 [0, max) 范围内的安全随机数。
// 当 max <= 0 时返回 0。失败时返回 error。
func SecureRandInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	// 使用 8 字节随机数取模，避免引入 math/big
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, NewError("failed to generate secure random number").Base(err)
	}
	// 转为 uint64 后取模，再转为 int（max <= math.MaxInt 保证不溢出）
	v := binary.LittleEndian.Uint64(buf[:]) % uint64(max)
	return int(v), nil //gosec:disable -- v 已通过取模限制在 [0, max) 范围内，max <= math.MaxInt，转换安全
}

// SecureRandUint32 使用 crypto/rand 生成 uint32 安全随机数。失败时返回 error。
func SecureRandUint32() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, NewError("failed to generate secure uint32").Base(err)
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// SafeIntFromUint64 安全地将 uint64 转为 int，溢出时返回 error。
func SafeIntFromUint64(v uint64) (int, error) {
	if v > uint64(math.MaxInt) {
		return 0, NewError("uint64 value overflow int")
	}
	return int(v), nil
}

// SafeUint64FromInt 安全地将 int 转为 uint64，负值时返回 error。
func SafeUint64FromInt(v int) (uint64, error) {
	if v < 0 {
		return 0, NewError("negative value cannot convert to uint64")
	}
	return uint64(v), nil
}

// SafeInt32FromInt 安全地将 int 转为 int32，溢出时返回 error。
func SafeInt32FromInt(v int) (int32, error) {
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, NewError("int value overflow int32")
	}
	return int32(v), nil
}

// SafeUint16FromInt 安全地将 int 转为 uint16，溢出时返回 error。
func SafeUint16FromInt(v int) (uint16, error) {
	if v > 65535 || v < 0 {
		return 0, NewError("int value overflow uint16")
	}
	return uint16(v), nil
}

// SafeIntFromUint16 安全地将 uint16 转为 int。
// 所有平台 int 均能容纳 uint16，此转换恒安全。
func SafeIntFromUint16(v uint16) int {
	return int(v)
}

// SafeIntFromInt64 安全地将 int64 转为 int，溢出时返回 error。
func SafeIntFromInt64(v int64) (int, error) {
	if v > int64(math.MaxInt) || v < int64(math.MinInt) {
		return 0, NewError("int64 value overflow int")
	}
	return int(v), nil
}

// ValidateFilePath 校验文件路径不包含 ".." 遍历序列，返回净化后的路径。
// 校验失败时返回 error。
func ValidateFilePath(path string) (string, error) {
	if strings.Contains(path, "..") {
		return "", NewError("path contains traversal sequence: " + path)
	}
	return filepath.Clean(path), nil
}

// SanitizeCommandArg 校验命令参数不包含路径遍历序列。
// exec.Command 不经过 shell，shell 元字符不构成注入风险，仅需校验路径遍历。
func SanitizeCommandArg(arg string) error {
	if strings.Contains(arg, "..") {
		return NewError("command argument contains path traversal sequence")
	}
	return nil
}
