package core

// GUIOption 图形化资产管理模式选项（onego 二开新增）
// 复用 InputOption.FormatterFilename (-F/--format) 指定初始加载的结果文件，
// -F 支持相对路径与绝对路径。
type GUIOption struct {
	GUI      bool   `long:"gui" description:"Bool, launch graphical asset management UI (onego)"`
	GUIPort  int    `long:"gui-port" default:"7474" description:"Int, GUI server listen port"`
	GUIDir   string `long:"gui-dir" description:"String, directory containing result files (.dat/json/csv), default: -F file dir or executable dir"`
	GUIDebug bool   `long:"gui-debug" description:"Bool, print GUI request-level debug logs"`
}
