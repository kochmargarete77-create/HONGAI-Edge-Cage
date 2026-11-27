//go:build windows

package main

import (
	"crypto/sha256"
	"errors"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	Length uint32
	Data   *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var kernel32 = syscall.NewLazyDLL("kernel32.dll")

func platformSeal(data []byte, root string) ([]byte, error) { return dpapi(data, false, root) }
func platformOpen(data []byte, root string) ([]byte, error) { return dpapi(data, true, root) }
func dpapi(data []byte, open bool, root string) ([]byte, error) {
	if len(data) == 0 || len(data) > maximumFrame {
		return nil, errors.New("INVALID_SEALED_PAYLOAD_SIZE")
	}
	input := dataBlob{uint32(len(data)), &data[0]}
	var output dataBlob
	context := sha256.Sum256([]byte("HONGAI-MCP-V1|" + root))
	entropy := dataBlob{uint32(len(context)), &context[0]}
	fn := crypt32.NewProc("CryptProtectData")
	if open {
		fn = crypt32.NewProc("CryptUnprotectData")
	}
	ok, _, _ := fn.Call(uintptr(unsafe.Pointer(&input)), 0, uintptr(unsafe.Pointer(&entropy)), 0, 0, 1, uintptr(unsafe.Pointer(&output)))
	if ok == 0 {
		return nil, errors.New("CURRENT_USER_PROTECTED_STORAGE_FAILED")
	}
	defer kernel32.NewProc("LocalFree").Call(uintptr(unsafe.Pointer(output.Data)))
	if output.Length > maximumFrame {
		return nil, errors.New("INVALID_DECRYPTED_PAYLOAD_SIZE")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Length))...), nil
}
