//go:build darwin

package main

import (
	"context"
	"os/exec"
	"time"
)

func presentEnvironmentFailure(code string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script := `on run argv
display alert "HONG AI · 启动诊断" message ("工作台暂未打开。错误代码：" & item 1 of argv & return & return & "请将代码发给服务人员；不要修改网络、清理账号或重启电脑。") as critical buttons {"好"} default button "好"
end run`
	_ = exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, code).Run()
}
