//go:build gui_native && darwin

// onego patch: macOS 退出支持。
// webview_go 不安装应用主菜单，导致 ⌘Q 无效；且其
// applicationShouldTerminateAfterLastWindowClosed 返回 NO，
// 关窗后 Go 进程（含 GUI HTTP 服务）残留继续占用端口。
// 这里补装主菜单退出项（⌘Q）与关窗通知监听，触发 terminate: 退出整个进程。
package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework WebKit
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

// purgeWebViewCache 启动时清空 WKWebView 默认数据仓库（含历史缓存的
// index.html/app.js/style.css）。WKWebView 磁盘缓存跨进程持久化，
// 早期无缓存头的旧页面会一直被复用导致 UI 停在旧版；本工具只加载
// localhost 页面、无登录态，每次启动清空是确保 UI 始终最新的可靠手段。
// removeDataOfTypes 的 completionHandler 在主队列回调，此处泵动
// RunLoop 同步等待完成（设 2 秒上限防卡死），确保后续加载不命中旧缓存。
static void purgeWebViewCache(void) {
	@autoreleasepool {
		WKWebsiteDataStore *store = [WKWebsiteDataStore defaultDataStore];
		NSSet *types = [WKWebsiteDataStore allWebsiteDataTypes];
		__block BOOL done = NO;
		[store removeDataOfTypes:types
				  modifiedSince:[NSDate distantPast]
			  completionHandler:^{ done = YES; }];
		NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:2.0];
		while (!done && [deadline timeIntervalSinceNow] > 0) {
			[[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
				beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
		}
	}
}

// installPlatformExit 安装 ⌘Q 退出菜单与关窗退出监听（进程级退出，释放端口）
static void installPlatformExit(void *window) {
	@autoreleasepool {
		// 主菜单：应用菜单下挂"退出 onego"（⌘Q），nil target 走响应链到
		// NSApplication 的 terminate:，退出整个进程
		NSMenu *menuBar = [[NSMenu alloc] init];
		NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
		[menuBar addItem:appMenuItem];
		[[NSApplication sharedApplication] setMainMenu:menuBar];
		NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"onego"];
		NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"退出 onego"
			action:@selector(terminate:) keyEquivalent:@"q"];
		[appMenu addItem:quitItem];
		[appMenuItem setSubmenu:appMenu];

		// 关窗（红色按钮）同样退出进程：webview 已占用 NSWindow delegate，
		// 不能覆盖，改用通知中心监听 NSWindowWillCloseNotification
		[[NSNotificationCenter defaultCenter]
			addObserverForName:NSWindowWillCloseNotification
			object:(NSWindow *)window
			queue:[NSOperationQueue mainQueue]
			usingBlock:^(NSNotification *note) {
				[[NSApplication sharedApplication] terminate:nil];
			}];
	}
}
*/
import "C"

import "unsafe"

func platformPreWindowSetup() {
	C.purgeWebViewCache()
}

func installPlatformExit(window unsafe.Pointer) {
	C.installPlatformExit(window)
}
