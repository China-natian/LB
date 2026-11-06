// Package gui 提供 onego 内嵌图形化资产管理能力。
// 仅使用 Go 标准库（net/http + embed + encoding/json），
// 解析复用 utils/parsers.ParseGogoData，不引入额外第三方依赖。
package gui

import (
	"embed"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/chainreactors/logs"
	parsers "github.com/chainreactors/utils/parsers"
)

//go:embed assets/index.html assets/style.css assets/app.js
var assetsFS embed.FS

// assetVersion 内嵌资源版本戳（css+js 内容哈希）：拼到引用 URL 上，
// 强制 WebView/浏览器每次升级后拉取最新资源，规避缓存旧页面导致 UI 新旧混乱
var assetVersion = func() string {
	h := fnv.New64a()
	for _, name := range []string{"assets/style.css", "assets/app.js"} {
		if b, err := assetsFS.ReadFile(name); err == nil {
			h.Write(b)
		}
	}
	return strconv.FormatUint(h.Sum64(), 36)
}()

// guiDebug 控制是否输出请求级调试日志（--gui-debug）
var guiDebug bool

// SetDebug 开启/关闭请求调试日志
func SetDebug(v bool) { guiDebug = v }

// ===== 数据模型 =====

type FileInfo struct {
	Name    string `json:"name"` // 展示名（隐藏文件去掉前导点）
	Path    string `json:"path"` // 加载用路径（保留原始文件名，含前导点）
	Size    string `json:"size"`
	ModTime string `json:"mod_time"`
}

type CategoryStat struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Count int    `json:"count"`
	IPs   int    `json:"ips"`
	Ports int    `json:"ports"`
}

type AssetRow struct {
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Status  string `json:"status"`
	Length  int    `json:"length"`
	Title   string `json:"title"`
	Tech    string `json:"tech"`
	Midware string `json:"midware"`
	Vulns   string `json:"vulns"`
	// onego patch: title 兜底来源（title=真实标题 finger=指纹兜底）与附加信息标记
	TitleSrc string   `json:"title_src,omitempty"`
	Marks    []string `json:"marks,omitempty"`
	Category string   `json:"category,omitempty"`
	// onego patch: 非 web 分类自适应表头用（均为 .dat 实测字段，不引入推测数据）
	Protocol string `json:"protocol,omitempty"`
	Extracts string `json:"extracts,omitempty"`
	// onego patch: 展示的指纹标签是否为原版 gogo 的推测指纹（f.IsGuess()），供前端弱化样式
	TitleGuess bool `json:"title_guess,omitempty"`
}

// RecordDetail 单条记录全字段详情（onego patch: 零信息丢失展示）
type RecordDetail struct {
	IP         string              `json:"ip"`
	Port       string              `json:"port"`
	Protocol   string              `json:"protocol"`
	Status     string              `json:"status"`
	Uri        string              `json:"uri,omitempty"`
	Host       string              `json:"host,omitempty"` // cert 域名
	Title      string              `json:"title"`
	Midware    string              `json:"midware,omitempty"`
	Length     int                 `json:"length"`
	Timing     int64               `json:"timing"`
	Category   string              `json:"category"`
	Frameworks []FrameItem         `json:"frameworks,omitempty"`
	Vulns      []VulnItem          `json:"vulns,omitempty"`
	Extracteds map[string][]string `json:"extracteds,omitempty"`
}

type FrameItem struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Product string   `json:"product,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Froms   []string `json:"froms,omitempty"`
	IsFocus bool     `json:"is_focus,omitempty"`
	IsGuess bool     `json:"is_guess,omitempty"`
}

type VulnItem struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Payload  string   `json:"payload,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// HostRow IP 级聚合行（onego patch: 主机视图，仅事实聚合不做推断）
type HostRow struct {
	IP          string   `json:"ip"`
	PortCount   int      `json:"port_count"`
	PortRange   string   `json:"port_range"`
	Ports       []string `json:"ports"`
	Services    []string `json:"services"` // 服务构成，如 "web×3"，来自已识别数据
	HasHost     bool     `json:"has_host"`
	HasExtracts bool     `json:"has_extracts"`
	HasVulns    bool     `json:"has_vulns"`
}

// ===== 分类规则（对齐平台 asset_classifier 的端口启发式） =====

var categoryOrder = []struct {
	Key  string
	Name string
}{
	{"web", "Web 资产"},
	{"db", "数据库"},
	{"remote", "远程管理"},
	{"middleware", "中间件/消息队列"},
	{"cloud", "云原生/容器"},
	{"win", "Windows 相关"},
	{"mail", "邮件服务"},
	{"other", "其他服务"},
}

// keywordCategory 按 状态/标题/指纹/中间件 关键词的分类规则（onego patch）：
// 分类必须基于扫描实测识别证据（协议状态名、指纹、banner 关键词），
// 不做端口推测——无任何识别信息的记录一律归"其他服务"，不误导渗透方向。
// 按序匹配，先命中先归类；关键词均以小写匹配。
var keywordCategory = []struct {
	Cat      string
	Keywords []string
}{
	{"remote", []string{"ssh-2.0", "ssh-1.", "openssh", "ssh2", "ssh", "rdp", "vnc", "telnet",
		"radmin", "pcanywhere", "x11", "winrm", "netconf", "ftp", "adb"}},
	{"db", []string{"mysql", "mariadb", "postgresql", "postgres", "mongodb", "redis",
		"memcached", "oracle", "mssql", "db2", "elasticsearch", "opensearch",
		"couchbase", "couchdb", "sybase", "hbase", "influxdb", "tidb", "clickhouse",
		"hadoop", "hive", "etcd", "consul"}},
	{"mail", []string{"smtp", "imap", "pop3", "exim", "postfix", "sendmail"}},
	{"win", []string{"kerberos", "ldap", "active directory", "microsoft-ds", "netbios",
		"smb", "msrpc"}},
	{"middleware", []string{"amqp", "mqtt", "zookeeper", "kafka", "rabbitmq", "activemq",
		"rocketmq", "pulsar", "nacos", "websphere", "weblogic", "dubbo", "jmx"}},
	{"cloud", []string{"docker", "kubelet", "kubernetes"}},
}

// genericFingers 泛化指纹：仅表示加密/传输层，不能作为具体服务的分类证据
var genericFingers = map[string]bool{"tls": true, "ssl": true, "http": true, "https": true}

// isMeaningfulStatus 状态是否为有信息量的协议识别结果
// （排除空值、tcp/open 等通用值与 HTTP 状态码）
func isMeaningfulStatus(s string) bool {
	if s == "" || s == "tcp" || s == "open" || s == "unknown" {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return false
	}
	return true
}

func keywordCategoryMatch(text string) (string, bool) {
	for _, rule := range keywordCategory {
		for _, kw := range rule.Keywords {
			if strings.Contains(text, kw) {
				return rule.Cat, true
			}
		}
	}
	return "", false
}

func classify(r *parsers.GOGOResult) string {
	if r.IsHttp() {
		return "web"
	}
	// onego patch: 分类只认实测识别证据，不做端口推测（数据真实性原则）。
	// 协议与状态字段都是 gogo 实测识别结果（如 protocol=smb、status=mysql），均作为证据
	for _, ev := range []string{r.Protocol, r.Status} {
		if isMeaningfulStatus(ev) {
			if c, ok := keywordCategoryMatch(strings.ToLower(ev)); ok {
				return c
			}
		}
	}
	if len(r.Frameworks) > 0 {
		names := make([]string, 0, len(r.Frameworks))
		for name := range r.Frameworks {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if genericFingers[name] {
				continue
			}
			if c, ok := keywordCategoryMatch(strings.ToLower(name)); ok {
				return c
			}
		}
	}
	if c, ok := keywordCategoryMatch(strings.ToLower(r.Title + " " + r.Midware)); ok {
		return c
	}
	return "other"
}

// ===== 服务状态 =====

type Server struct {
	dir string

	mu      sync.RWMutex
	current *parsers.GOGOData
	file    string
}

func NewServer(dir string) *Server {
	return &Server{dir: dir}
}

// ===== HTTP 入口 =====

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, _ := assetsFS.ReadFile("assets/index.html")
		// onego patch: 引用 URL 加版本戳，绕过 WebView/浏览器对旧 css/js 的缓存
		html := strings.ReplaceAll(string(data), `href="style.css"`, `href="style.css?v=`+assetVersion+`"`)
		html = strings.ReplaceAll(html, `src="app.js"`, `src="app.js?v=`+assetVersion+`"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// onego patch: 内嵌资源禁缓存，避免 WebView/浏览器缓存旧页面导致升级后 UI 新旧混乱
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(html))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		data, _ := assetsFS.ReadFile("assets/style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		data, _ := assetsFS.ReadFile("assets/app.js")
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	mux.HandleFunc("/api/files", s.apiFiles)
	mux.HandleFunc("/api/load", s.apiLoad)
	mux.HandleFunc("/api/summary", s.apiSummary)
	mux.HandleFunc("/api/assets", s.apiAssets)
	mux.HandleFunc("/api/export", s.apiExport)
	// onego patch: 单记录全字段详情与 IP 级主机聚合
	mux.HandleFunc("/api/record", s.apiRecord)
	mux.HandleFunc("/api/hosts", s.apiHosts)

	// 访问日志中间件：记录请求路径与 UA，便于排查窗口加载问题
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guiDebug {
			fmt.Printf("[gui-debug] %s %s ua=%s\n", r.Method, r.URL.Path, r.UserAgent())
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ===== API 实现 =====

func (s *Server) apiFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var files []FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".dat" && ext != ".json" && ext != ".csv" && ext != ".jsonl" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    strings.TrimPrefix(e.Name(), "."),
			Path:    e.Name(),
			Size:    humanSize(info.Size()),
			ModTime: info.ModTime().Format("2006-01-02 15:04"),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	writeJSON(w, map[string]interface{}{"files": files})
}

func (s *Server) apiLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		File string `json:"file"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.File == "" {
		writeErr(w, 400, "缺少 file 参数")
		return
	}

	var full, name string
	if filepath.IsAbs(req.File) {
		// 绝对路径（-F 指定的外部结果文件）：校验存在性与扩展名后直接加载
		ext := strings.ToLower(filepath.Ext(req.File))
		if ext != ".dat" && ext != ".json" && ext != ".csv" && ext != ".jsonl" {
			writeErr(w, 400, "不支持的文件类型")
			return
		}
		if _, err := os.Stat(req.File); err != nil {
			writeErr(w, 404, "文件不存在: "+req.File)
			return
		}
		full = req.File
		name = filepath.Base(req.File)
	} else {
		// 防止路径穿越，仅允许加载工作目录内的文件
		name = filepath.Base(req.File)
		full = filepath.Join(s.dir, name)
	}

	data, err := parsers.ParseGogoData(full)
	if err != nil {
		writeErr(w, 500, "解析失败: "+err.Error())
		return
	}

	s.mu.Lock()
	s.current = data
	s.file = name
	s.mu.Unlock()

	writeJSON(w, map[string]interface{}{"count": len(data.Data), "file": name})
}

func (s *Server) apiSummary(w http.ResponseWriter, r *http.Request) {
	rows := s.classifiedRows()
	stats := make(map[string]*CategoryStat)
	for _, c := range categoryOrder {
		stats[c.Key] = &CategoryStat{Key: c.Key, Name: c.Name}
	}
	ipSet := make(map[string]map[string]bool)
	portSet := make(map[string]map[string]bool)
	for _, item := range rows {
		st := stats[item.cat]
		st.Count++
		if ipSet[item.cat] == nil {
			ipSet[item.cat] = make(map[string]bool)
			portSet[item.cat] = make(map[string]bool)
		}
		ipSet[item.cat][item.r.Ip] = true
		portSet[item.cat][item.r.Port] = true
	}
	var out []CategoryStat
	for _, c := range categoryOrder {
		st := stats[c.Key]
		st.IPs = len(ipSet[c.Key])
		st.Ports = len(portSet[c.Key])
		out = append(out, *st)
	}
	writeJSON(w, map[string]interface{}{"categories": out})
}

func (s *Server) apiAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cat := q.Get("category")
	filter := q.Get("filter")
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 2000 {
		pageSize = 200
	}

	var matched []classified
	filterCounter := map[string]int{}
	for _, item := range s.classifiedRows() {
		if cat != "" && item.cat != cat {
			continue
		}
		key := filterKey(item.r, cat)
		filterCounter[key]++
		if filter != "" && filter != "__all__" && key != filter {
			continue
		}
		// onego patch: 全文搜索（ip: 前缀为 IP 精确匹配），用于详情面板回填与 IP 筛选
		if search != "" && !matchSearch(item.r, search) {
			continue
		}
		matched = append(matched, item)
	}

	// 筛选项按数量降序，数量相同按名称升序，保证每次请求顺序稳定
	type kv struct {
		K string
		V int
	}
	var kvs []kv
	for k, v := range filterCounter {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].V != kvs[j].V {
			return kvs[i].V > kvs[j].V
		}
		return kvs[i].K < kvs[j].K
	})
	var filters [][]string
	for _, p := range kvs {
		filters = append(filters, []string{fmt.Sprintf("%s (%d)", p.K, p.V), p.K})
	}

	total := len(matched)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var rows []AssetRow
	// onego patch: 按记录自身分类渲染（修复"全部"视角下 web 记录被按非 web 渲染）
	for _, it := range matched[start:end] {
		rows = append(rows, toRow(it.r, it.cat))
	}
	writeJSON(w, map[string]interface{}{
		"assets":  rows,
		"total":   total,
		"filters": filters,
	})
}

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cat := q.Get("category")
	filter := q.Get("filter")

	var rows []AssetRow
	for _, item := range s.classifiedRows() {
		if cat != "" && item.cat != cat {
			continue
		}
		if filter != "" && filter != "__all__" && filterKey(item.r, cat) != filter {
			continue
		}
		rows = append(rows, toRow(item.r, item.cat))
	}

	// onego patch: WKWebView 不支持附件下载，window.location 跳转会用 CSV
	// 文本替换整个 GUI 且无法返回；改为服务端直接写入 .dat 同目录，
	// 返回保存路径供界面提示，用户到该路径取文件即可
	base := strings.TrimLeft(strings.TrimSuffix(filepath.Base(s.file), filepath.Ext(s.file)), ".")
	name := fmt.Sprintf("%s_export_%s.csv", base, time.Now().Format("20060102-150405"))
	path := filepath.Join(s.dir, name)
	f, err := os.Create(path)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer f.Close()
	// UTF-8 BOM，保证 Excel 中文不乱码
	f.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(f)
	cw.Write([]string{"IP", "端口", "状态码", "长度", "标题", "技术栈", "中间件", "漏洞"})
	for _, row := range rows {
		cw.Write([]string{row.IP, row.Port, row.Status, strconv.Itoa(row.Length),
			row.Title, row.Tech, row.Midware, row.Vulns})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"path": path, "count": len(rows)})
}

// apiRecord 返回单条记录的全字段详情（onego patch: 模块一·零信息丢失）
func (s *Server) apiRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip, port := q.Get("ip"), q.Get("port")
	if ip == "" || port == "" {
		writeErr(w, 400, "缺少 ip/port 参数")
		return
	}
	data := s.currentData()
	if data == nil {
		writeErr(w, 400, "尚未加载结果文件")
		return
	}
	for _, rec := range data.Data {
		if rec.Ip == ip && rec.Port == port {
			writeJSON(w, toRecordDetail(rec))
			return
		}
	}
	writeErr(w, 404, "未找到该记录")
}

// apiHosts 按 IP 聚合当前筛选下的全部端口（onego patch: 模块二·事实聚合）
func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cat := q.Get("category")
	filter := q.Get("filter")
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))

	groups := make(map[string][]*parsers.GOGOResult)
	for _, item := range s.classifiedRows() {
		if cat != "" && item.cat != cat {
			continue
		}
		if filter != "" && filter != "__all__" && filterKey(item.r, cat) != filter {
			continue
		}
		if search != "" && !matchSearch(item.r, search) {
			continue
		}
		groups[item.r.Ip] = append(groups[item.r.Ip], item.r)
	}

	hosts := make([]HostRow, 0, len(groups))
	for ip, recs := range groups {
		hosts = append(hosts, aggregateHost(ip, recs))
	}
	sort.Slice(hosts, func(i, j int) bool { return ipKey(hosts[i].IP) < ipKey(hosts[j].IP) })
	writeJSON(w, map[string]interface{}{"hosts": hosts, "total": len(hosts)})
}

// ===== 内部辅助 =====

type classified struct {
	cat string
	r   *parsers.GOGOResult
}

func (s *Server) classifiedRows() []classified {
	s.mu.RLock()
	data := s.current
	s.mu.RUnlock()
	if data == nil {
		return nil
	}
	out := make([]classified, 0, len(data.Data))
	for _, r := range data.Data {
		// onego patch: icmp 是主机存活探测结果，不是服务资产，不参与展示统计
		if strings.EqualFold(r.Protocol, "icmp") {
			continue
		}
		out = append(out, classified{cat: classify(r), r: r})
	}
	return out
}

func (s *Server) currentData() *parsers.GOGOData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// matchSearch 全文搜索匹配（onego patch）：
// "ip:" 前缀为 IP 精确匹配；否则在 IP/端口/标题/中间件/cert域名/指纹/漏洞/提取信息中做子串匹配
func matchSearch(r *parsers.GOGOResult, q string) bool {
	if strings.HasPrefix(q, "ip:") {
		return r.Ip == strings.TrimPrefix(q, "ip:")
	}
	var b strings.Builder
	b.WriteString(r.Ip)
	b.WriteByte(' ')
	b.WriteString(r.Port)
	b.WriteByte(' ')
	b.WriteString(r.Title)
	b.WriteByte(' ')
	b.WriteString(r.Midware)
	b.WriteByte(' ')
	b.WriteString(r.Host)
	b.WriteByte(' ')
	b.WriteString(r.Status)
	for name, f := range r.Frameworks {
		b.WriteByte(' ')
		b.WriteString(name)
		if f != nil && f.Attributes != nil && f.Version != "" {
			b.WriteByte(' ')
			b.WriteString(f.Version)
		}
	}
	for name := range r.Vulns {
		b.WriteByte(' ')
		b.WriteString(name)
	}
	for _, vs := range r.Extracteds {
		for _, v := range vs {
			b.WriteByte(' ')
			b.WriteString(v)
		}
	}
	return strings.Contains(strings.ToLower(b.String()), q)
}

// serviceName 记录的服务名（onego patch: 只取已识别数据，不做推断）：
// http → web；已识别状态名 → 状态名；指纹 → 首个指纹名；否则端口号本身
func serviceName(r *parsers.GOGOResult) string {
	if r.IsHttp() {
		return "web"
	}
	if r.Status != "" && r.Status != "tcp" {
		return r.Status
	}
	if f := r.GetFirstFramework(); f != nil {
		return f.Name
	}
	return "port:" + r.Port
}

// aggregateHost 聚合单 IP 的全部记录为 HostRow（onego patch）
func aggregateHost(ip string, recs []*parsers.GOGOResult) HostRow {
	row := HostRow{IP: ip, PortCount: len(recs)}
	ports := make([]string, 0, len(recs))
	portNums := make([]int, 0, len(recs))
	svcCount := map[string]int{}
	for _, r := range recs {
		ports = append(ports, r.Port)
		if n, err := strconv.Atoi(r.Port); err == nil {
			portNums = append(portNums, n)
		}
		svcCount[serviceName(r)]++
		if r.Host != "" {
			row.HasHost = true
		}
		if len(r.Extracteds) > 0 {
			row.HasExtracts = true
		}
		if len(r.Vulns) > 0 {
			row.HasVulns = true
		}
	}
	sort.Strings(ports)
	row.Ports = ports
	if len(portNums) > 0 {
		sort.Ints(portNums)
		row.PortRange = fmt.Sprintf("%d-%d", portNums[0], portNums[len(portNums)-1])
	}
	type svcKV struct {
		name string
		n    int
	}
	var svcs []svcKV
	for name, n := range svcCount {
		svcs = append(svcs, svcKV{name, n})
	}
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].n != svcs[j].n {
			return svcs[i].n > svcs[j].n
		}
		return svcs[i].name < svcs[j].name
	})
	for _, s := range svcs {
		if s.n > 1 {
			row.Services = append(row.Services, fmt.Sprintf("%s×%d", s.name, s.n))
		} else {
			row.Services = append(row.Services, s.name)
		}
	}
	return row
}

// ipKey IPv4 数值化用于自然排序
func ipKey(ip string) uint32 {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return 0xFFFFFFFF
	}
	return binary.BigEndian.Uint32(p)
}

// toRecordDetail 将记录转换为全字段详情（onego patch）
func toRecordDetail(r *parsers.GOGOResult) RecordDetail {
	cat := classify(r)
	d := RecordDetail{
		IP:         r.Ip,
		Port:       r.Port,
		Protocol:   r.Protocol,
		Status:     r.Status,
		Uri:        r.Uri,
		Host:       r.Host,
		Title:      sanitizeTitle(r.Title),
		Midware:    r.Midware,
		Length:     r.Length,
		Timing:     r.Timing,
		Category:   cat,
		Extracteds: r.Extracteds,
	}
	if len(r.Frameworks) > 0 {
		names := make([]string, 0, len(r.Frameworks))
		for name := range r.Frameworks {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			f := r.Frameworks[name]
			item := FrameItem{Name: name}
			if f != nil {
				item.Tags = f.Tags
				item.IsFocus = f.IsFocus
				item.IsGuess = f.IsGuess()
				for from := range f.Froms {
					item.Froms = append(item.Froms, parsers.FrameFromMap[from])
				}
				sort.Strings(item.Froms)
				if f.Attributes != nil {
					item.Version = f.Version
					item.Product = f.Product
				}
			}
			d.Frameworks = append(d.Frameworks, item)
		}
	}
	if len(r.Vulns) > 0 {
		names := make([]string, 0, len(r.Vulns))
		for name := range r.Vulns {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			v := r.Vulns[name]
			item := VulnItem{Name: name}
			if v != nil {
				item.Severity = parsers.SeverityMap[v.SeverityLevel]
				item.Tags = v.Tags
				item.Payload = strings.TrimSpace(v.GetPayload())
				item.Detail = strings.TrimSpace(v.GetDetail())
			}
			d.Vulns = append(d.Vulns, item)
		}
	}
	return d
}

func filterKey(r *parsers.GOGOResult, cat string) string {
	if cat == "web" {
		return r.Status
	}
	// onego patch: 非 web 筛选标签按识别证据聚合——识别到的具体指纹名
	//（mysql/redis/ssh…）优先于状态名、协议名；仅泛化指纹(tls/ssl)不构成识别证据。
	// 无识别语义（open/tcp）时按端口聚合。全部来自 .dat 实测识别结果，不引入推测信息
	if name := fingerName(r); name != "" {
		return name
	}
	if isMeaningfulStatus(r.Status) {
		return r.Status
	}
	if isMeaningfulStatus(r.Protocol) {
		return r.Protocol
	}
	return r.Port
}

// sanitizeTitle 清理标题展示内容（onego patch）：
// 1. 还原/去除历史数据中 AsciiEncode 产生的 \uXXXX 转义（控制字符去除，可打印字符解码还原）；
// 2. 去除 \xXX 转义序列；
// 3. 去除控制字符；清理后为空则视为二进制响应，返回空串。
var (
	hexEscapeRE     = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	unicodeEscapeRE = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

func sanitizeTitle(title string) string {
	if title == "" {
		return ""
	}
	cleaned := unicodeEscapeRE.ReplaceAllStringFunc(title, func(m string) string {
		code, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return ""
		}
		r := rune(code)
		if unicode.IsControl(r) || r == 0 {
			return ""
		}
		return string(r)
	})
	cleaned = hexEscapeRE.ReplaceAllString(cleaned, "")
	cleaned = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, cleaned)
	return strings.TrimSpace(cleaned)
}

func toRow(r *parsers.GOGOResult, cat string) AssetRow {
	row := AssetRow{IP: r.Ip, Port: r.Port, Category: cat}
	if cat == "web" {
		row.Status = r.Status
		row.Length = r.Length
		row.Title = sanitizeTitle(r.Title)
		row.Midware = r.Midware
		if r.Frameworks != nil {
			var names []string
			for name := range r.Frameworks {
				names = append(names, name)
			}
			sort.Strings(names)
			row.Tech = strings.Join(names, ",")
		}
	} else {
		// 非 Web：状态列显示服务名；标题列优先显示具体指纹（原始 banner 常为
		// 二进制片段，指纹识别结果更具可读性），无指纹时退回清理后的 banner；
		// 技术栈列填充全部指纹+版本，保证概览行可见关键信息
		if r.Status != "" && r.Status != "tcp" {
			row.Status = r.Status
		} else {
			row.Status = r.Protocol
		}
		// onego patch: 非 web 自适应表头字段——协议与提取信息直接取自 .dat 实测数据
		row.Protocol = r.Protocol
		row.Extracts = extractsLabel(r)
		if fl := fingerLabel(r); fl != "" {
			row.Title = fl
			row.TitleSrc = "finger"
			row.TitleGuess = fingerGuessed(r)
		} else if t := sanitizeTitle(r.Title); t != "" {
			row.Title = t
			row.TitleSrc = "title"
		}
		row.Tech = techLabel(r)
	}
	// onego patch: 标题缺失时用首个指纹名+版本灰色兜底，保证每行有可读的服务特征
	if row.Title == "" {
		if fb := fallbackTitle(r); fb != "" {
			row.Title = fb
			row.TitleSrc = "finger"
			row.TitleGuess = fingerGuessed(r)
		}
	} else if row.TitleSrc == "" {
		row.TitleSrc = "title"
	}
	// onego patch: 附加信息标记点——提示该记录还有更多详情可查看
	var marks []string
	if len(r.Extracteds) > 0 {
		marks = append(marks, "extracts")
	}
	if r.Host != "" {
		marks = append(marks, "cert")
	}
	if len(r.Vulns) > 0 {
		marks = append(marks, "vuln")
	}
	row.Marks = marks
	if r.Vulns != nil && len(r.Vulns) > 0 {
		var names []string
		for name := range r.Vulns {
			names = append(names, name)
		}
		sort.Strings(names)
		row.Vulns = strings.Join(names, ",")
	}
	return row
}

// fallbackTitle 标题兜底（onego patch）：按指纹名排序取首个，拼上版本号（如有）
func fallbackTitle(r *parsers.GOGOResult) string {
	if len(r.Frameworks) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Frameworks))
	for name := range r.Frameworks {
		names = append(names, name)
	}
	sort.Strings(names)
	f := r.Frameworks[names[0]]
	// 防御：历史数据反序列化后 Attributes 可能为 nil
	if f != nil && f.Attributes != nil && f.Version != "" {
		return names[0] + " " + f.Version
	}
	return names[0]
}

// fingerName 首个具体指纹名（不含版本，供筛选标签按服务聚合——
// mysql 5.7.38-log 与 mysql 8.0.32 归入同一 mysql 标签）
func fingerName(r *parsers.GOGOResult) string {
	if len(r.Frameworks) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Frameworks))
	for name := range r.Frameworks {
		if !genericFingers[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// fingerLabel 非 web 记录的首选展示标签：排序后首个具体指纹名+版本（如有）。
// tls/ssl 等泛化指纹不参与——它们不携带服务信息，此时 banner 更有价值。
func fingerLabel(r *parsers.GOGOResult) string {
	if len(r.Frameworks) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Frameworks))
	for name := range r.Frameworks {
		if !genericFingers[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	f := r.Frameworks[names[0]]
	if f != nil && f.Attributes != nil && f.Version != "" {
		return names[0] + " " + f.Version
	}
	return names[0]
}

// fingerGuessed 展示的首选指纹是否为原版 gogo 的推测指纹（f.IsGuess()），
// 选取规则与 fingerLabel 保持一致；前端据此对推测指纹做灰色斜体弱化展示
func fingerGuessed(r *parsers.GOGOResult) bool {
	if len(r.Frameworks) == 0 {
		return false
	}
	names := make([]string, 0, len(r.Frameworks))
	for name := range r.Frameworks {
		if !genericFingers[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return false
	}
	sort.Strings(names)
	f := r.Frameworks[names[0]]
	return f != nil && f.IsGuess()
}

// techLabel 全部指纹名+版本列表（非 web 技术栈列，概览即见关键信息）
func techLabel(r *parsers.GOGOResult) string {
	if len(r.Frameworks) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Frameworks))
	for name := range r.Frameworks {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		f := r.Frameworks[name]
		if f != nil && f.Attributes != nil && f.Version != "" {
			parts = append(parts, name+" "+f.Version)
		} else {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ",")
}

// extractsLabel 提取信息摘要（非 web"提取信息"列）：按类型名排序拼接，
// 内容全部来自 .dat 实测提取结果，不做任何推测补全
func extractsLabel(r *parsers.GOGOResult) string {
	if len(r.Extracteds) == 0 {
		return ""
	}
	keys := make([]string, 0, len(r.Extracteds))
	for k := range r.Extracteds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := r.Extracteds[k]
		if len(vs) == 0 {
			continue
		}
		parts = append(parts, k+": "+strings.Join(vs, " "))
	}
	return strings.Join(parts, "; ")
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ===== 启动入口 =====

// Start 启动本地 GUI 服务。port 为监听端口，initialFile 为可选初始 .dat 文件。
// openWindow 返回值表示窗口是否已关闭（原生窗口模式），
// 浏览器模式下返回 false，服务将持续驻留直到 Ctrl+C。
func Start(dir string, port int, initialFile string, openWindow func(url string) bool) error {
	logs.Log = logs.NewLogger(0)

	srv := NewServer(dir)
	listen := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", listen, err)
	}

	httpSrv := &http.Server{Handler: srv.Handler()}
	go httpSrv.Serve(ln)

	url := fmt.Sprintf("http://%s", listen)
	if initialFile != "" {
		url += "/?file=" + neturl.QueryEscape(initialFile)
	}
	logs.Log.Importantf("onego GUI 已启动: %s", url)

	if openWindow != nil {
		if closed := openWindow(url); closed {
			// 原生窗口已关闭，退出服务
			httpSrv.Close()
			return nil
		}
	}

	// 浏览器模式：进程驻留，Ctrl+C 退出
	select {}
}
