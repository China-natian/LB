package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/chainreactors/onego/v2/core"
	"github.com/chainreactors/onego/v2/gui"
	"github.com/jessevdk/go-flags"
)

func init() {
	log.SetOutput(ioutil.Discard)
}

func Gogo() {
	// onego 二开：先解析一次参数判断是否进入 GUI 模式，
	// 非 GUI 场景完整走上游 RunWithArgs 标准流程，不改变原有行为。
	var probe core.Runner
	probeParser := flags.NewParser(&probe, flags.Default&^flags.PrintErrors)
	probeParser.Usage = core.Usage()
	if _, err := probeParser.Parse(); err != nil {
		// help 与错误输出均交给 go-flags 的 Error.Error()，与上游 RunWithArgs 行为一致
		fmt.Println(err.Error())
		return
	}
	if probe.GUI {
		runGUI(&probe)
		return
	}

	err := core.RunWithArgs(context.Background(), os.Args[1:], core.RunOptions{})
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); !ok || flagsErr.Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}
	time.Sleep(100 * time.Millisecond)
}

// runGUI 进入图形化资产管理模式，不执行扫描。
// 初始文件复用 -F/--format（支持绝对路径）。
// 结果目录优先级：--gui-dir 显式指定 > -F 文件所在目录 > 可执行文件所在目录。
func runGUI(r *core.Runner) {
	dir := r.GUIDir
	initial := r.FormatterFilename

	if initial != "" {
		if abs, err := filepath.Abs(initial); err == nil {
			initial = abs
		}
		// 未显式指定 --gui-dir 且 -F 指向已存在的文件时，文件列表目录跟随 -F
		if dir == "" {
			if info, err := os.Stat(initial); err == nil && !info.IsDir() {
				dir = filepath.Dir(initial)
			}
		}
	} else if dir == "" {
		// 默认扫描 onego 可执行文件所在目录的结果文件
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Dir(exe)
		} else {
			dir = "."
		}
	}

	fmt.Println(core.Banner())
	gui.SetDebug(r.GUIDebug)
	if err := gui.Start(dir, r.GUIPort, initial, gui.PlatformOpenWindow); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
