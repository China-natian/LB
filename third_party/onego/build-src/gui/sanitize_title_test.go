package gui

import "testing"

// onego patch 单元测试：GUI 标题展示兜底清理

func TestSanitizeTitle(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hex 转义全清", `\x00\x00\x06\x04\x00\x00\x00\x00\x05\x00`, ""},
		{"混合保留可读部分", `\x00\x00` + "HTTP/2", "HTTP/2"},
		{"控制字符清除", "标题\x00\x01测试", "标题测试"},
		{"正常标题不动", "Solr Admin", "Solr Admin"},
		{"中文不动", "后台管理系统", "后台管理系统"},
		{"DEL unicode 转义清除", `\u007f`, ""},
		{"DEL 转义后保留可读部分", `\u007fELF`, "ELF"},
		{"可打印 unicode 转义还原", `Welcome\u4e2d`, "Welcome中"},
		{"混合多种转义", `\x00\u007fSSH-2.0`, "SSH-2.0"},
	}
	for _, c := range cases {
		if got := sanitizeTitle(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
