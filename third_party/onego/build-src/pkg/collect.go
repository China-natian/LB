package pkg

import (
	"bytes"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chainreactors/utils/httputils"
	"github.com/chainreactors/utils/iutils"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func CollectSocketResponse(result *Result, socketContent []byte) {
	if ishttp, _ := GetStatusCode(socketContent); ishttp {
		result.Protocol = "http"
		CollectParsedResponse(result, newResponseFromRaw(socketContent))
	} else {
		result.Content = socketContent
		if title := httputils.MatchTitle(socketContent); title != "" {
			result.HasTitle = true
			result.Title = title
		} else if isLikelyBinary(socketContent) {
			// onego patch: 二进制协议响应（如 http/2 帧、RPC 报文）不作为标题，
			// 避免 \x00 等不可读字节进入结果
			result.Title = ""
		} else {
			// onego patch: 剥离 DEL 等控制字符（如 \x7fELF 类响应），只保留可打印部分
			result.Title = cleanBannerTitle(httputils.MatchCharacter(socketContent))
		}
		result.AddExtracts(Extractors.Extract(string(socketContent), true))
	}
}

// isLikelyBinary 判断响应内容是否为二进制数据：
// 采样前 512 字节，含 NUL 字节或不可打印字符占比过高即视为二进制。
// 可打印的 ASCII banner（FTP/SSH/MySQL 欢迎语等）不受影响。
func isLikelyBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	sample := content
	if len(sample) > 512 {
		sample = sample[:512]
	}
	bad := 0
	for _, b := range sample {
		if b == 0 || (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b == 0x7f {
			bad++
		}
	}
	return bad*5 > len(sample) // 不可打印占比超过 20%
}

// cleanBannerTitle 剥离 banner 标题中的控制字符（DEL、转义序列残留等），
// 只保留可打印部分并去除首尾空白。
func cleanBannerTitle(title string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, title)
	return strings.TrimSpace(cleaned)
}

// RepairTitleEncoding 修复非 UTF-8 编码的标题（常见于未声明 charset 的 GBK 页面）。
// 已是合法 UTF-8 的标题原样返回；否则尝试按 GBK 解码，
// 解码后中日韩字符占比足够高才采纳，避免误伤。
func RepairTitleEncoding(title string) string {
	if title == "" || utf8.ValidString(title) {
		return title
	}
	out, err := simplifiedchinese.GBK.NewDecoder().String(title)
	if err != nil {
		return title
	}
	total, cjk := 0, 0
	for _, r := range out {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			continue
		}
		total++
		if r >= 0x2E80 && r <= 0x9FFF {
			cjk++
		}
	}
	if total > 0 && cjk*2 >= total { // CJK 占比超过一半
		return out
	}
	return title
}

func CollectHttpResponse(result *Result, resp *http.Response) {
	if resp == nil {
		return
	}

	CollectParsedResponse(result, newResponseFromHTTP(resp, int64(DefaultMaxSize*2)))
}

func CollectParsedResponse(result *Result, resp *httputils.Response) {
	if resp == nil {
		return
	}
	result.IsHttp = true
	result.Httpresp = resp

	// tolower 忽略大小写
	for i, c := range result.Httpresp.History {
		result.Httpresp.History[i].Raw = bytes.ToLower(c.Raw)
	}
	result.Content = bytes.ToLower(result.Httpresp.Raw)
	// onego patch: 记录 web 响应内容长度，随结果持久化到 .dat，供 GUI 展示
	result.Length = len(result.Httpresp.Raw)
	result.Status = iutils.ToString(resp.Resp.StatusCode)
	result.Midware = result.Httpresp.Server
	result.Title = result.Httpresp.Title
	result.HasTitle = result.Httpresp.HasTitle
	result.AddExtracts(Extractors.Extract(string(result.Httpresp.Raw), true))
}

// GetStatusCode 从socket中获取http状态码
func GetStatusCode(content []byte) (bool, string) {
	if len(content) > 12 && bytes.HasPrefix(content, []byte("HTTP")) {
		return true, string(content[9:12])
	}
	return false, "tcp"
}

func FormatCertDomains(domains []string) []string {
	var hosts []string
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			domain = strings.Trim(domain, "*.")
		}
		hosts = append(hosts, domain)
	}
	return iutils.StringsUnique(hosts)
}

func CollectTLS(result *Result, resp *http.Response) {
	domains := peerDNSNames(resp)
	result.Host = strings.Join(domains, ",")
	if len(domains) > 0 {
		// 经验公式: 通常只有cdn会绑定超过2个host, 正常情况只有一个host或者带上www的两个host
		result.HttpHosts = append(result.HttpHosts, FormatCertDomains(domains)...)
	}
}
