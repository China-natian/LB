//go:build gui_native && windows

// onego patch: Windows 下 WebView2 运行时存在性检测。
// Windows Server 2019 等系统不自带 Edge/WebView2，webview 原生窗口无法创建，
// 需在创建窗口前检测并降级为浏览器驻留模式，避免进程空转无窗口。
package gui

import (
	"syscall"
	"unsafe"
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	regCloseKey      = advapi32.NewProc("RegCloseKey")
	regQueryValueExW = advapi32.NewProc("RegQueryValueExW")
)

const (
	hkeyLocalMachine = syscall.Handle(0x80000002)
	hkeyCurrentUser  = syscall.Handle(0x80000001)
	keyRead          = 0x20019
)

// WebView2 运行时 Evergreen 客户端状态注册表 GUID（微软官方检测方式）
const webview2ClientKey = `SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

// regValueExists 检查注册表键下 pv（版本号）值是否存在
func regValueExists(root syscall.Handle, subKey string) bool {
	kptr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return false
	}
	var h syscall.Handle
	r, _, _ := regOpenKeyExW.Call(uintptr(root), uintptr(unsafe.Pointer(kptr)), 0,
		keyRead, uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return false
	}
	defer regCloseKey.Call(uintptr(h))

	name, _ := syscall.UTF16PtrFromString("pv")
	var typ, size uint32
	r, _, _ = regQueryValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(name)), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)))
	return r == 0 && size > 0
}

// webview2Available 检测本机是否安装 Evergreen WebView2 Runtime
func webview2Available() bool {
	return regValueExists(hkeyLocalMachine, webview2ClientKey) ||
		regValueExists(hkeyLocalMachine, `SOFTWARE\WOW6432Node\`+webview2ClientKey) ||
		regValueExists(hkeyCurrentUser, webview2ClientKey)
}
