//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

func replaceFile(from, to string) error {
	f, e := syscall.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	t, e := syscall.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	ok, _, _ := kernel32.NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(t)), 9)
	if ok == 0 {
		return errors.New("ATOMIC_FILE_REPLACE_FAILED_NO_UNSAFE_DELETE_FALLBACK")
	}
	return nil
}
