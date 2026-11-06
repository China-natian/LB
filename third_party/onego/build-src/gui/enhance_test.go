package gui

import (
	"reflect"
	"testing"

	parsers "github.com/chainreactors/utils/parsers"
)

// onego patch 单元测试：标题兜底、标记点、主机聚合、全文搜索

func TestFallbackTitle(t *testing.T) {
	cases := []struct {
		name string
		r    *parsers.GOGOResult
		want string
	}{
		{"无指纹返回空", &parsers.GOGOResult{}, ""},
		{"单指纹带版本", &parsers.GOGOResult{
			Frameworks: parsers.Frameworks{"nginx": parsers.NewFrameworkWithVersion("nginx", parsers.FrameFromFingers, "1.18.0")},
		}, "nginx 1.18.0"},
		{"单指纹无版本", &parsers.GOGOResult{
			Frameworks: parsers.Frameworks{"redis": parsers.NewFramework("redis", parsers.FrameFromNmap)},
		}, "redis"},
		{"多指纹按名称排序取首个", &parsers.GOGOResult{
			Frameworks: parsers.Frameworks{
				"tomcat": parsers.NewFramework("tomcat", parsers.FrameFromFingers),
				"apache": parsers.NewFramework("apache", parsers.FrameFromFingers),
			},
		}, "apache"},
		{"Attributes 为 nil 不 panic", &parsers.GOGOResult{
			Frameworks: parsers.Frameworks{"mysql": {Name: "mysql"}},
		}, "mysql"},
	}
	for _, c := range cases {
		if got := fallbackTitle(c.r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestToRowTitleFallbackAndMarks(t *testing.T) {
	// 标题缺失 + 有指纹 → 指纹兜底，TitleSrc=finger
	r := &parsers.GOGOResult{
		Ip: "1.1.1.1", Port: "8080", Protocol: "http", Status: "200",
		Frameworks: parsers.Frameworks{"shiro": parsers.NewFramework("shiro", parsers.FrameFromFingers)},
	}
	row := toRow(r, "web")
	if row.Title != "shiro" || row.TitleSrc != "finger" {
		t.Errorf("兜底失败: title=%q src=%q", row.Title, row.TitleSrc)
	}

	// 真实标题优先，TitleSrc=title
	r.Title = "后台登录"
	row = toRow(r, "web")
	if row.Title != "后台登录" || row.TitleSrc != "title" {
		t.Errorf("真实标题优先失败: title=%q src=%q", row.Title, row.TitleSrc)
	}

	// 标记点：extracts / cert / vuln
	r2 := &parsers.GOGOResult{
		Ip: "2.2.2.2", Port: "80", Protocol: "http", Status: "200", Title: "t",
		Host:       "example.com",
		Extracteds: map[string][]string{"ip": {"10.0.0.1"}},
		Vulns:      parsers.Vulns{"shiro_default_key": &parsers.Vuln{Name: "shiro_default_key", SeverityLevel: parsers.SeverityHIGH}},
	}
	row2 := toRow(r2, "web")
	want := []string{"extracts", "cert", "vuln"}
	if !reflect.DeepEqual(row2.Marks, want) {
		t.Errorf("标记点: got %v want %v", row2.Marks, want)
	}

	// 无任何附加信息 → 标记点为空
	r3 := &parsers.GOGOResult{Ip: "3.3.3.3", Port: "22", Protocol: "tcp", Status: "tcp"}
	if got := toRow(r3, "remote"); len(got.Marks) != 0 {
		t.Errorf("无附加信息不应有标记点: got %v", got.Marks)
	}
}

// TestToRowNonWebSmartTitle 非 web 智能标题：具体指纹优先于原始 banner，
// 泛化指纹(tls)不参与，技术栈列填充全部指纹
func TestToRowNonWebSmartTitle(t *testing.T) {
	// 有具体指纹：标题=指纹名+版本，banner 被忽略，技术栈填充
	r := &parsers.GOGOResult{
		Ip: "4.4.4.4", Port: "3269", Protocol: "tcp", Status: "open",
		Title: "\n5.6.51-log 二进制片段",
		Frameworks: parsers.Frameworks{
			"mysql": parsers.NewFrameworkWithVersion("mysql", parsers.FrameFromFingers, "5.6.51-log"),
		},
	}
	row := toRow(r, "db")
	if row.Title != "mysql 5.6.51-log" || row.TitleSrc != "finger" {
		t.Errorf("指纹优先失败: title=%q src=%q", row.Title, row.TitleSrc)
	}
	if row.Tech != "mysql 5.6.51-log" {
		t.Errorf("技术栈填充失败: %q", row.Tech)
	}
	if row.Category != "db" {
		t.Errorf("分类字段: %q", row.Category)
	}
	// onego patch: 非 web 自适应表头字段——协议与提取信息取自 .dat 实测数据
	if row.Protocol != "tcp" {
		t.Errorf("协议字段: %q", row.Protocol)
	}
	r.Extracteds = map[string][]string{"ip": {"10.1.1.1"}, "domain": {"a.com", "b.com"}}
	row = toRow(r, "db")
	if row.Extracts != "domain: a.com b.com; ip: 10.1.1.1" {
		t.Errorf("提取信息摘要: %q", row.Extracts)
	}

	// 仅泛化指纹 tls：退回 banner
	r2 := &parsers.GOGOResult{
		Ip: "5.5.5.5", Port: "4243", Protocol: "tcp", Status: "open", Title: "Docker Daemon",
		Frameworks: parsers.Frameworks{"tls": nil},
	}
	row2 := toRow(r2, "cloud")
	if row2.Title != "Docker Daemon" || row2.TitleSrc != "title" {
		t.Errorf("泛化指纹应退回 banner: title=%q src=%q", row2.Title, row2.TitleSrc)
	}

	// 无指纹无 banner：标题为空（不硬造信息）
	r3 := &parsers.GOGOResult{Ip: "6.6.6.6", Port: "6666", Protocol: "tcp", Status: "open"}
	if got := toRow(r3, "other"); got.Title != "" {
		t.Errorf("无信息不应硬造标题: %q", got.Title)
	}
}

func TestServiceName(t *testing.T) {
	cases := []struct {
		name string
		r    *parsers.GOGOResult
		want string
	}{
		{"http 归为 web", &parsers.GOGOResult{Port: "80", Protocol: "http"}, "web"},
		{"已识别状态名", &parsers.GOGOResult{Port: "3306", Protocol: "tcp", Status: "mysql"}, "mysql"},
		{"状态为 tcp 时取指纹", &parsers.GOGOResult{Port: "9092", Protocol: "tcp", Status: "tcp",
			Frameworks: parsers.Frameworks{"kafka": parsers.NewFramework("kafka", parsers.FrameFromNmap)}}, "kafka"},
		{"无任何识别取端口号", &parsers.GOGOResult{Port: "12345", Protocol: "tcp", Status: "tcp"}, "port:12345"},
	}
	for _, c := range cases {
		if got := serviceName(c.r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestAggregateHost(t *testing.T) {
	recs := []*parsers.GOGOResult{
		{Ip: "10.0.0.5", Port: "80", Protocol: "http", Status: "200"},
		{Ip: "10.0.0.5", Port: "8080", Protocol: "http", Status: "200"},
		{Ip: "10.0.0.5", Port: "443", Protocol: "https", Status: "200", Host: "a.example.com"},
		{Ip: "10.0.0.5", Port: "3306", Protocol: "tcp", Status: "mysql"},
		{Ip: "10.0.0.5", Port: "9999", Protocol: "tcp", Status: "tcp",
			Extracteds: map[string][]string{"ip": {"10.0.0.9"}},
			Vulns:      parsers.Vulns{"redis_unauthorized": &parsers.Vuln{Name: "redis_unauthorized"}}},
	}
	h := aggregateHost("10.0.0.5", recs)
	if h.PortCount != 5 {
		t.Errorf("端口数: got %d want 5", h.PortCount)
	}
	if h.PortRange != "80-9999" {
		t.Errorf("端口范围: got %q want 80-9999", h.PortRange)
	}
	if !reflect.DeepEqual(h.Ports, []string{"3306", "443", "80", "8080", "9999"}) {
		t.Errorf("端口列表: got %v", h.Ports)
	}
	// 服务构成：web×3 排首位（事实聚合，无推断规则）
	if len(h.Services) < 1 || h.Services[0] != "web×3" {
		t.Errorf("服务构成: got %v", h.Services)
	}
	if !h.HasHost || !h.HasExtracts || !h.HasVulns {
		t.Errorf("附加标记: %+v", h)
	}
}

func TestIpKey(t *testing.T) {
	if !(ipKey("1.1.1.1") < ipKey("10.0.0.1") && ipKey("10.0.0.1") < ipKey("192.168.1.1")) {
		t.Errorf("IP 排序错误: %d %d %d", ipKey("1.1.1.1"), ipKey("10.0.0.1"), ipKey("192.168.1.1"))
	}
}

func TestMatchSearch(t *testing.T) {
	r := &parsers.GOGOResult{
		Ip: "10.0.0.5", Port: "8080", Protocol: "http", Status: "200",
		Title:      "后台登录",
		Host:       "oa.example.com",
		Frameworks: parsers.Frameworks{"shiro": parsers.NewFrameworkWithVersion("shiro", parsers.FrameFromFingers, "1.4")},
		Extracteds: map[string][]string{"ip": {"172.16.0.9"}},
		Vulns:      parsers.Vulns{"shiro_default_key": &parsers.Vuln{Name: "shiro_default_key"}},
	}
	cases := []struct {
		q    string
		want bool
	}{
		{"ip:10.0.0.5", true},
		{"ip:10.0.0.6", false},
		{"shiro", true},             // 指纹名
		{"1.4", true},               // 指纹版本
		{"oa.example.com", true},    // cert 域名
		{"172.16.0.9", true},        // 提取信息
		{"shiro_default_key", true}, // 漏洞名
		{"不存在的词", false},
	}
	for _, c := range cases {
		if got := matchSearch(r, c.q); got != c.want {
			t.Errorf("q=%q: got %v want %v", c.q, got, c.want)
		}
	}
}

// TestToRowTitleGuess 展示指纹标签的推测标识（onego patch）：
// fingers 实测识别的确定指纹不标记；原版 gogo 推测指纹（FrameFromGUESS）标记为 guess，
// 前端据此灰色斜体弱化展示，避免推测指纹误导渗透方向
func TestToRowTitleGuess(t *testing.T) {
	// 确定指纹：fingers 识别命中，不标记
	r1 := &parsers.GOGOResult{Ip: "1.1.1.1", Port: "22", Protocol: "tcp",
		Frameworks: parsers.Frameworks{
			"ssh": parsers.NewFrameworkWithVersion("ssh", parsers.FrameFromFingers, "2.0"),
		}}
	if row := toRow(r1, "remote"); row.TitleGuess {
		t.Errorf("确定指纹不应标记 guess: title=%q", row.Title)
	}
	// 推测指纹：仅 guess 来源，标记且标题取指纹名
	r2 := &parsers.GOGOResult{Ip: "2.2.2.2", Port: "6379", Protocol: "tcp", Status: "open",
		Frameworks: parsers.Frameworks{
			"redis": parsers.NewFramework("redis", parsers.FrameFromGUESS),
		}}
	row2 := toRow(r2, "db")
	if row2.TitleSrc != "finger" || !row2.TitleGuess {
		t.Errorf("推测指纹应标记 guess: title=%q src=%q guess=%v", row2.Title, row2.TitleSrc, row2.TitleGuess)
	}
	// 混合来源（fingers+guess）：IsGuess 为 false，不标记
	r3 := &parsers.GOGOResult{Ip: "3.3.3.3", Port: "3306", Protocol: "tcp",
		Frameworks: parsers.Frameworks{"mysql": func() *parsers.Framework {
			f := parsers.NewFramework("mysql", parsers.FrameFromFingers)
			f.Froms[parsers.FrameFromGUESS] = true
			return f
		}()}}
	if row := toRow(r3, "db"); row.TitleGuess {
		t.Errorf("含实测来源的指纹不应标记 guess: title=%q", row.Title)
	}
}
