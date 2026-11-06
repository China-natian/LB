package pkg

import "testing"

// onego patch 单元测试：标题乱码修复链路

func TestIsLikelyBinary(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"http2 settings 帧", []byte{0, 0, 6, 4, 0, 0, 0, 0, 5, 0, 0, 0xff, 0, 1}, true},
		{"全零", []byte{0, 0, 0, 0}, true},
		{"FTP banner", []byte("220 FTP Server ready\r\n"), false},
		{"SSH banner", []byte("SSH-2.0-OpenSSH_8.9\r\n"), false},
		{"MySQL 握手（含部分二进制）", []byte("J\x00\x00\x00\x0a8.0.32\x00"), true},
		{"空", []byte{}, false},
	}
	for _, c := range cases {
		if got := isLikelyBinary(c.in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestCleanBannerTitle(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ELF 魔数剥离 DEL", "\x7fELF\x01\x01\x01", "ELF"},
		{"正常 banner 不动", "SSH-2.0-OpenSSH_8.9\r\n", "SSH-2.0-OpenSSH_8.9"},
		{"全控制字符", "\x7f\x01\x02", ""},
	}
	for _, c := range cases {
		if got := cleanBannerTitle(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestRepairTitleEncoding(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"正常 UTF-8 不动", "后台管理系统", "后台管理系统"},
		{"GBK 中文修复", string([]byte{0xba, 0xf3, 0xcc, 0xa8, 0xb9, 0xdc, 0xc0, 0xed, 0xcf, 0xb5, 0xcd, 0xb3}), "后台管理系统"},
		{"纯 ASCII", "Index of /", "Index of /"},
		{"空", "", ""},
	}
	for _, c := range cases {
		if got := RepairTitleEncoding(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
