//go:build gui_native && !windows

// onego patch: 非 Windows 平台（macOS WKWebView）无运行时缺失问题，恒可用
package gui

func webview2Available() bool { return true }
