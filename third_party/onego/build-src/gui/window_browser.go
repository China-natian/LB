//go:build !gui_native

// 浏览器回退实现（A 档，默认）：零额外依赖，调用系统默认浏览器打开。
package gui

import (
	"os/exec"
	"runtime"

	"github.com/chainreactors/logs"
)

// PlatformOpenWindow 用默认浏览器打开 GUI 地址（非阻塞，返回 false 表示服务继续驻留）
func PlatformOpenWindow(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		logs.Log.Errorf("无法自动打开浏览器，请手动访问: %s", url)
	}
	return false
}
