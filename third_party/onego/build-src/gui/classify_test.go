package gui

import (
	"testing"

	parsers "github.com/chainreactors/utils/parsers"
)

// onego patch 单元测试：资产分类规则（只认实测识别证据，不做端口推测）

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		r    *parsers.GOGOResult
		want string
	}{
		{"非标端口 SSH banner", &parsers.GOGOResult{Port: "2223", Protocol: "tcp", Title: "SSH-2.0-OpenS"}, "remote"},
		{"非标端口完整 OpenSSH banner", &parsers.GOGOResult{Port: "20022", Protocol: "tcp", Title: "SSH-2.0-OpenSSH_8.9"}, "remote"},
		{"状态名 ssh 识别", &parsers.GOGOResult{Port: "22", Protocol: "tcp", Status: "ssh"}, "remote"},
		{"HTTP 协议", &parsers.GOGOResult{Port: "8080", Protocol: "http", Title: "xxx"}, "web"},
		{"HTTPS 协议", &parsers.GOGOResult{Port: "8443", Protocol: "https"}, "web"},
		{"状态名 mysql 识别", &parsers.GOGOResult{Port: "3306", Protocol: "tcp", Status: "mysql"}, "db"},
		{"非标端口 Redis banner", &parsers.GOGOResult{Port: "16379", Protocol: "tcp", Title: "redis 6.2"}, "db"},
		{"指纹名命中", &parsers.GOGOResult{Port: "9999", Protocol: "tcp", Frameworks: parsers.Frameworks{"telnet": nil}}, "remote"},
		{"win 端口上的 mysql 指纹归数据库", &parsers.GOGOResult{Port: "3269", Protocol: "tcp", Status: "open",
			Frameworks: parsers.Frameworks{"mysql": parsers.NewFrameworkWithVersion("mysql", parsers.FrameFromFingers, "5.6.51-log")}}, "db"},
		{"win 端口上的 ldap 状态归 Windows", &parsers.GOGOResult{Port: "3269", Protocol: "tcp", Status: "ldap"}, "win"},
		{"协议识别名 smb 归 Windows", &parsers.GOGOResult{Port: "445", Protocol: "smb", Status: "tcp"}, "win"},
		// onego patch: 数据真实性——无识别证据不做端口推测，一律归其他服务
		{"常见数据库端口但无任何识别信息", &parsers.GOGOResult{Port: "3306", Protocol: "tcp"}, "other"},
		{"50000 端口仅 tcp open", &parsers.GOGOResult{Port: "50000", Protocol: "tcp", Status: "open"}, "other"},
		{"仅 tls 泛化指纹不构成证据", &parsers.GOGOResult{Port: "4243", Protocol: "tcp", Status: "open",
			Frameworks: parsers.Frameworks{"tls": nil}}, "other"},
		{"无特征", &parsers.GOGOResult{Port: "12345", Protocol: "tcp", Status: "open"}, "other"},
		// onego patch: 存储/大数据类指纹归数据库（elasticsearch/couchbase/hadoop 等）
		{"9300 elasticsearch 指纹归数据库", &parsers.GOGOResult{Port: "9300", Protocol: "tcp", Status: "open",
			Frameworks: parsers.Frameworks{"elasticsearch": nil}}, "db"},
		{"couchbase 指纹归数据库", &parsers.GOGOResult{Port: "8091", Protocol: "tcp",
			Frameworks: parsers.Frameworks{"couchbase": nil}}, "db"},
		{"sybase 状态名归数据库", &parsers.GOGOResult{Port: "5000", Protocol: "tcp", Status: "sybase"}, "db"},
		{"hadoop 指纹归数据库", &parsers.GOGOResult{Port: "9000", Protocol: "tcp",
			Frameworks: parsers.Frameworks{"hadoop": nil}}, "db"},
	}
	for _, c := range cases {
		if got := classify(c.r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// TestFilterKey 筛选标签维度：web 按状态码；非 web 按识别指纹优先，
// 无识别证据时退回状态名/端口（全部来自实测数据）
func TestFilterKey(t *testing.T) {
	cases := []struct {
		name string
		r    *parsers.GOGOResult
		cat  string
		want string
	}{
		{"web 按状态码", &parsers.GOGOResult{Status: "403"}, "web", "403"},
		{"db mysql 指纹优先于 open 状态", &parsers.GOGOResult{Port: "3306", Protocol: "tcp",
			Status: "open", Frameworks: parsers.Frameworks{
				"mysql": parsers.NewFrameworkWithVersion("mysql", parsers.FrameFromFingers, "5.7.38-log"),
			}}, "db", "mysql"},
		{"不同版本 mysql 归并同一标签", &parsers.GOGOResult{Port: "3306", Protocol: "tcp",
			Status: "open", Frameworks: parsers.Frameworks{
				"mysql": parsers.NewFrameworkWithVersion("mysql", parsers.FrameFromFingers, "8.0.32"),
			}}, "db", "mysql"},
		{"仅 tls 泛化指纹且状态无服务语义按端口", &parsers.GOGOResult{Port: "4243", Protocol: "tcp",
			Status: "open", Frameworks: parsers.Frameworks{"tls": nil}}, "cloud", "4243"},
		{"remote 状态名 ssh", &parsers.GOGOResult{Port: "22", Protocol: "tcp", Status: "ssh"}, "remote", "ssh"},
		{"协议识别名 smb 作为标签", &parsers.GOGOResult{Port: "445", Protocol: "smb", Status: "tcp"}, "win", "smb"},
		{"无指纹无服务状态按端口", &parsers.GOGOResult{Port: "3306", Protocol: "tcp", Status: "tcp"}, "db", "3306"},
	}
	for _, c := range cases {
		if got := filterKey(c.r, c.cat); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
