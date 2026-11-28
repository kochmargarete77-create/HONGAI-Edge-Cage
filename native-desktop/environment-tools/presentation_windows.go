//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func presentEnvironmentFailure(code string) {
	message, e := syscall.UTF16PtrFromString("HONG AI 工作台暂未打开。\n\n错误代码：" + code + "\n\n请将此代码发给服务人员。不要为处理此问题修改网络、清理账号或重启电脑。")
	if e != nil {
		return
	}
	title, _ := syscall.UTF16PtrFromString("HONG AI · 启动诊断")
	_, _, _ = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10|0x10000)
}
