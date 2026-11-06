//go:build gui_native

// 原生窗口实现（B 档）：使用 webview_go 弹出独立 App 式窗口。
// 编译时需加 -tags gui_native，macOS 使用系统 WKWebView，Windows 使用 WebView2。
package gui

import (
	"github.com/chainreactors/logs"
	"github.com/webview/webview_go"
)

// PlatformOpenWindow 打开原生 GUI 窗口（阻塞直到窗口关闭，返回 true）
func PlatformOpenWindow(url string) bool {
	// onego patch: Windows Server 2019 等无 Edge/WebView2 运行时，原生窗口
	// 无法创建（进程空转无窗口）；检测缺失时降级为浏览器驻留模式并提示
	if !webview2Available() {
		logs.Log.Errorf("未检测到 WebView2 运行时，原生窗口不可用；如需原生窗口请安装 Evergreen WebView2 Runtime: https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		logs.Log.Importantf("已切换浏览器模式，请用 Chrome/Edge 等现代浏览器访问 %s （Ctrl+C 退出）", url)
		return false
	}
	// onego patch: 创建窗口前清空 WebView 历史缓存（macOS），确保加载最新内嵌资源
	platformPreWindowSetup()
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("onego 资产管理")
	w.SetSize(1280, 820, webview.HintNone)
	// onego patch: 补装 ⌘Q 退出菜单与关窗退出（macOS），避免进程残留占用端口
	installPlatformExit(w.Window())
	w.Navigate(url)
	w.Run()
	return true
}
