// mkdat: 生成合成 gogo .dat 测试文件（复用真实加密格式: deflate+xor, 行 JSON Lines）。
// 仅用于 GUI 功能测试，测试后可删除。
package main

import (
	"fmt"
	"os"

	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/fileutils"
)

func main() {
	filename := "test.dat"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}

	// ModeAppend 不会截断旧文件，先删除保证重复生成时数据不叠加
	os.Remove(filename)

	file, err := fileutils.NewFile(filename, fileutils.ModeAppend, true, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var cursor int
	file.Encoder = func(i []byte) []byte {
		bs := encode.XorEncode(encode.MustDeflateCompress(i), fileutils.Key, cursor)
		cursor += len(bs)
		return bs
	}
	file.ClosedAppend = "[\"done\"]\n"

	// 第 0 行: 扫描配置头 (解析时被跳过)
	file.WriteLine(`{"target":"10.0.0.0/24","ports":"top100","mod":"scan","json_type":"scan"}`)

	// Web 资产
	file.WriteLine(`{"ip":"10.0.0.5","port":"80","protocol":"http","status":"200","title":"后台登录系统","midware":"nginx/1.20.1","length":3421,"frameworks":{"nginx":{"attributes":{"version":"1.20.1"}},"php":{},"shiro":{"is_focus":true,"tags":["java","auth"]}},"vulns":{"thinkphp-rce":{"severity":4,"tags":["rce"],"payload":{"path":"/index.php?s=/Index/\\\\think\\\\app/invokefunction"},"detail":{"response":["ThinkPHP 5.0.23"]}}},"extracted":{"ip":["10.0.0.6","10.0.0.11"],"email":["admin@corp.example.com"]}}`)
	file.WriteLine(`{"ip":"10.0.0.5","port":"443","protocol":"https","status":"200","title":"OA 办公平台","midware":"nginx/1.20.1","length":18204,"host":"oa.corp.example.com","frameworks":{"nginx":{"attributes":{"version":"1.20.1"}},"vue":{},"java":{}},"extracted":{"ip":["10.0.0.6"]}}`)
	file.WriteLine(`{"ip":"10.0.0.12","port":"8080","protocol":"http","status":"404","title":"Whitelabel Error Page","midware":"Apache Tomcat/9.0.50","length":431,"frameworks":{"java":{},"spring":{"attributes":{"version":"2.6.3"}}},"vulns":{"springboot-actuator":{"severity":2,"tags":["leak"],"detail":{"path":["/actuator/env"]}}}}`)
	file.WriteLine(`{"ip":"10.0.0.12","port":"8000","protocol":"http","status":"401","title":"Unauthorized","length":152,"frameworks":{"django":{},"python":{}}}`)
	file.WriteLine(`{"ip":"10.0.0.18","port":"7001","protocol":"http","status":"200","title":"WebLogic Server 控制台","midware":"WebLogic/12.2.1.4","length":6890,"frameworks":{"weblogic":{"attributes":{"version":"12.2.1.4"},"is_focus":true},"java":{}},"vulns":{"weblogic-cve-2020-14882":{"severity":4,"tags":["rce"]}}}`)
	file.WriteLine(`{"ip":"10.0.0.21","port":"8848","protocol":"http","status":"200","title":"Nacos","length":2210,"frameworks":{"nacos":{},"spring":{}}}`)
	// 空标题 + 指纹：验证标题兜底（灰色斜体显示指纹名+版本）
	file.WriteLine(`{"ip":"10.0.0.30","port":"443","protocol":"https","status":"302","length":0,"host":"iis.corp.example.com","frameworks":{"iis":{"attributes":{"version":"10.0"}},"asp.net":{}}}`)
	// 空标题 + 多指纹：验证兜底取排序首个
	file.WriteLine(`{"ip":"10.0.0.40","port":"8443","protocol":"https","status":"200","length":921,"frameworks":{"tomcat":{"attributes":{"version":"8.5.61"}},"zabbix":{}},"extracted":{"domain":["db.corp.example.com"]}}`)

	// 数据库
	file.WriteLine(`{"ip":"10.0.0.5","port":"3306","protocol":"tcp","status":"mysql","title":"MySQL 5.7.36","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.6","port":"6379","protocol":"tcp","status":"redis","title":"Redis 未授权访问","length":0,"vulns":{"redis-unauthorized":{}}}`)
	file.WriteLine(`{"ip":"10.0.0.7","port":"5432","protocol":"tcp","status":"postgres","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.8","port":"27017","protocol":"tcp","status":"mongodb","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.9","port":"9200","protocol":"tcp","status":"elasticsearch","length":0}`)

	// 远程管理
	file.WriteLine(`{"ip":"10.0.0.5","port":"22","protocol":"tcp","status":"ssh","title":"OpenSSH 8.2p1","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.20","port":"3389","protocol":"tcp","status":"rdp","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.21","port":"5900","protocol":"tcp","status":"vnc","length":0}`)

	// 中间件
	file.WriteLine(`{"ip":"10.0.0.11","port":"9092","protocol":"tcp","status":"kafka","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.11","port":"2181","protocol":"tcp","status":"zookeeper","length":0}`)

	// 云原生
	file.WriteLine(`{"ip":"10.0.0.15","port":"2375","protocol":"tcp","status":"docker","title":"Docker API 未授权","length":0,"vulns":{"docker-api-unauthorized":{}}}`)
	file.WriteLine(`{"ip":"10.0.0.16","port":"10250","protocol":"tcp","status":"kubelet","length":0}`)

	// Windows
	file.WriteLine(`{"ip":"10.0.0.20","port":"445","protocol":"tcp","status":"smb","title":"Windows Server 2019","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.20","port":"135","protocol":"tcp","status":"msrpc","length":0}`)
	// win 端口(3269)上的 mysql 指纹：验证证据优先分类归入数据库，标题智能显示指纹；
	// 附带 extracted 验证非 web 表头"提取信息"列
	file.WriteLine(`{"ip":"10.0.0.79","port":"3269","protocol":"tcp","status":"open","title":"\\u000a\\u00005.6.51-log","length":0,"frameworks":{"mysql":{"attributes":{"version":"5.6.51-log"}}},"extracted":{"ip":["10.20.30.40"],"domain":["db.internal.corp"]}}`)
	file.WriteLine(`{"ip":"10.0.0.79","port":"3389","protocol":"tcp","status":"rdp","length":0}`)
	// 仅 tls 泛化指纹的 4243：无识别证据，如实归其他服务
	file.WriteLine(`{"ip":"10.0.0.17","port":"4243","protocol":"tcp","status":"open","length":0,"frameworks":{"tls":{}}}`)
	// elasticsearch transport 端口(9300)指纹识别：应归数据库而非其他服务
	file.WriteLine(`{"ip":"10.0.0.93","port":"9300","protocol":"tcp","status":"open","length":0,"frameworks":{"elasticsearch":{}}}`)
	// 50000 端口仅 tcp open 无任何识别信息：不做端口推测，归其他服务
	file.WriteLine(`{"ip":"10.0.0.94","port":"50000","protocol":"tcp","status":"open","length":0}`)
	// mysql 乱码 banner 无指纹：验证退回清理后的 banner 显示
	file.WriteLine(`{"ip":"10.0.0.80","port":"3306","protocol":"tcp","status":"tcp","title":"\\u000a\\u0000\\u0015\\u00045.7.28-log","length":0}`)

	// 邮件
	file.WriteLine(`{"ip":"10.0.0.25","port":"25","protocol":"tcp","status":"smtp","title":"Postfix","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.25","port":"110","protocol":"tcp","status":"pop3","length":0}`)

	// 其他
	file.WriteLine(`{"ip":"10.0.0.30","port":"8888","protocol":"tcp","status":"tcp","length":0}`)
	file.WriteLine(`{"ip":"10.0.0.31","port":"2222","protocol":"tcp","status":"ssh","length":0}`)
	// 非标端口 SSH banner：验证关键词二级分类归入远程管理
	file.WriteLine(`{"ip":"10.0.0.66","port":"2223","protocol":"tcp","status":"open","title":"SSH-2.0-OpenSSH_8.9","length":0}`)
	// DEL 控制字符 unicode 转义：验证 sanitizeTitle 清理（字面 \u007f）
	file.WriteLine(`{"ip":"10.0.0.67","port":"9100","protocol":"tcp","status":"open","title":"\\u007fELF","length":0}`)

	if err := file.Close(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("written:", filename)
}
