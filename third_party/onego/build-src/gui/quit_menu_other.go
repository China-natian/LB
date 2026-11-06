//go:build gui_native && !darwin

// onego patch: macOS 之外的原生窗口无 ⌘Q 菜单缺失与 WKWebView 缓存问题，空实现
package gui

import "unsafe"

func platformPreWindowSetup()              {}
func installPlatformExit(_ unsafe.Pointer) {}
