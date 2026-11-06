package pkg

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chainreactors/utils/parsers"
)

func makeConfigLine(jsonType string) string {
	cfg := &parsers.GOGOConfig{
		IP:           "10.0.0.0/24",
		Ports:        "80",
		Mod:          "default",
		JsonType:     jsonType,
		VersionLevel: 1,
		Exploit:      "none",
		Threads:      1000,
	}
	b, _ := json.Marshal(cfg)
	return string(b)
}

func makeScanLine(ip, port string) string {
	r := parsers.NewGOGOResult(ip, port)
	r.Protocol = "tcp"
	r.Status = "open"
	b, _ := json.Marshal(r)
	return string(b)
}

func TestLoadResultFile_NormalScan(t *testing.T) {
	var b strings.Builder
	b.WriteString(makeConfigLine("scan") + "\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString(makeScanLine("10.0.0.2", "443") + "\n")
	b.WriteString(`["done"]` + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData, got %T", result)
	}
	if len(rd.Data) != 2 {
		t.Fatalf("expected 2 results, got %d", len(rd.Data))
	}
	if rd.Config.IP != "10.0.0.0/24" {
		t.Errorf("expected config IP 10.0.0.0/24, got %s", rd.Config.IP)
	}
}

func TestLoadResultFile_NormalScanNoDone(t *testing.T) {
	var b strings.Builder
	b.WriteString(makeConfigLine("scan") + "\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString(makeScanLine("10.0.0.2", "443") + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData, got %T", result)
	}
	if len(rd.Data) != 2 {
		t.Fatalf("expected 2 results, got %d", len(rd.Data))
	}
}

func TestLoadResultFile_BrokenConfigHeader(t *testing.T) {
	var b strings.Builder
	// Simulates the broken version: error string instead of JSON config
	b.WriteString("json: unsupported type: func(string, string, time.Duration) (net.Conn, error)\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString(makeScanLine("10.0.0.2", "443") + "\n")
	b.WriteString(makeScanLine("10.0.0.3", "8080") + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData from broken .dat, got %T", result)
	}
	if len(rd.Data) != 3 {
		t.Fatalf("expected 3 results recovered from broken .dat, got %d", len(rd.Data))
	}
	if rd.Data[0].Ip != "10.0.0.1" {
		t.Errorf("expected first IP 10.0.0.1, got %s", rd.Data[0].Ip)
	}
}

func TestLoadResultFile_BrokenConfigWithDone(t *testing.T) {
	var b strings.Builder
	b.WriteString("json: unsupported type: func(string, string)\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString(`["done"]` + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData, got %T", result)
	}
	if len(rd.Data) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rd.Data))
	}
}

func TestLoadResultFile_MalformedDataLinesSkipped(t *testing.T) {
	var b strings.Builder
	b.WriteString(makeConfigLine("scan") + "\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString("this is not json\n")
	b.WriteString(makeScanLine("10.0.0.2", "443") + "\n")
	b.WriteString(`["done"]` + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData, got %T", result)
	}
	if len(rd.Data) != 2 {
		t.Fatalf("expected 2 results (bad line skipped), got %d", len(rd.Data))
	}
}

func TestLoadResultFile_EmptyInput(t *testing.T) {
	result := LoadResultFile(bytes.NewReader([]byte("")))
	if result != nil {
		t.Fatalf("expected nil for empty input, got %T", result)
	}
}

func TestLoadResultFile_OnlyGarbage(t *testing.T) {
	result := LoadResultFile(bytes.NewReader([]byte("garbage line 1\ngarbage line 2\n")))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected *ResultsData (empty fallback), got %T", result)
	}
	if len(rd.Data) != 0 {
		t.Fatalf("expected 0 results for all-garbage input, got %d", len(rd.Data))
	}
}

func TestLoadResultFile_SmartMalformedLineSkipped(t *testing.T) {
	var b strings.Builder
	b.WriteString(makeConfigLine("smartb") + "\n")
	b.WriteString(`{"192.168.1.0/24":["80","443"]}` + "\n")
	b.WriteString("not json\n")
	b.WriteString(`{"192.168.2.0/24":["8080"]}` + "\n")
	b.WriteString(`["done"]` + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	sr, ok := result.(*SmartResult)
	if !ok || sr == nil {
		t.Fatalf("expected *SmartResult, got %T", result)
	}
	if len(sr.Data) != 2 {
		t.Fatalf("expected 2 smart entries (bad line skipped), got %d", len(sr.Data))
	}
}

func TestLoadResultFile_MultipleSegments(t *testing.T) {
	var b strings.Builder
	// Segment 1
	b.WriteString(makeConfigLine("scan") + "\n")
	b.WriteString(makeScanLine("10.0.0.1", "80") + "\n")
	b.WriteString(`["done"]` + "\n")
	// Segment 2
	b.WriteString(makeConfigLine("scan") + "\n")
	b.WriteString(makeScanLine("10.0.0.2", "443") + "\n")
	b.WriteString(`["done"]` + "\n")

	result := LoadResultFile(bytes.NewReader([]byte(b.String())))
	rd, ok := result.(*ResultsData)
	if !ok || rd == nil {
		t.Fatalf("expected merged *ResultsData, got %T", result)
	}
	if len(rd.Data) != 2 {
		t.Fatalf("expected 2 results from merged segments, got %d", len(rd.Data))
	}
}

func TestConfigToJson_Valid(t *testing.T) {
	config := &Config{
		GOGOConfig: &parsers.GOGOConfig{
			IP:    "10.0.0.0/24",
			Ports: "80",
			Mod:   "default",
		},
		RunnerOpt: DefaultRunnerOption,
	}
	out := config.ToJson("scan")
	if !strings.Contains(out, `"json_type":"scan"`) {
		t.Fatalf("expected json_type in output, got: %s", out)
	}
	if strings.Contains(out, "RunnerOpt") {
		t.Fatalf("RunnerOpt should be excluded from JSON, got: %s", out)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("ToJson output is not valid JSON: %v", err)
	}
}

func TestConfigToJson_RunnerOptExcluded(t *testing.T) {
	config := &Config{
		GOGOConfig: &parsers.GOGOConfig{IP: "10.0.0.1/32"},
		RunnerOpt:  DefaultRunnerOption,
	}
	out := config.ToJson("scan")

	if strings.Contains(out, "Exploit") {
		t.Fatalf("RunnerOpt fields should not appear in JSON output: %s", out)
	}
	if strings.Contains(out, "ProxyDial") {
		t.Fatalf("func fields should not appear in JSON output: %s", out)
	}
}
