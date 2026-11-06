package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/chainreactors/utils/parsers"
)

func scanResult(ip, port string) *Result {
	return &Result{GOGOResult: &parsers.GOGOResult{Ip: ip, Port: port}}
}

func TestScanSummaryClassification(t *testing.T) {
	ResetScanSummary()
	open := scanResult("10.0.0.1", "22")
	open.Open = true
	refused := scanResult("10.0.0.1", "80")
	refused.Error = "connect: connection refused"
	timeout := scanResult("10.0.0.1", "443")
	timeout.Error = "i/o timeout"
	denied := scanResult("10.0.0.1", "3306")
	denied.Error = "permission denied"
	unknown := scanResult("10.0.0.1", "8080")
	special := scanResult("10.0.0.1", "snmp")
	special.Open = true
	excluded := scanResult("10.0.0.2", "")
	excluded.Excluded = true

	for _, result := range []*Result{open, refused, timeout, denied, unknown, special, excluded} {
		RecordScanResult(result)
	}

	path := filepath.Join(t.TempDir(), "summary.json")
	if err := WriteScanSummary(path); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary ScanSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary.Schema != ScanSummarySchema {
		t.Fatalf("schema = %q, want %q", summary.Schema, ScanSummarySchema)
	}
	first := summary.Targets["10.0.0.1"]
	if first == nil {
		t.Fatal("missing target 10.0.0.1")
	}
	if first.Tested != 5 {
		t.Errorf("tested = %d, want 5", first.Tested)
	}
	if first.Open != 1 || first.Closed != 1 || first.Filtered != 1 || first.Error != 1 || first.Unknown != 1 {
		t.Errorf("unexpected counts: %+v", first)
	}
	if len(first.OpenPorts) != 1 || first.OpenPorts[0] != "22" {
		t.Errorf("open ports = %v, want [22]", first.OpenPorts)
	}
	if first.Special["snmp"] != 1 {
		t.Errorf("special = %v, want snmp:1", first.Special)
	}
	second := summary.Targets["10.0.0.2"]
	if second == nil || second.Excluded != 1 || second.Tested != 0 {
		t.Fatalf("unexpected excluded target: %+v", second)
	}
}

func TestScanSummaryDeduplicatesPorts(t *testing.T) {
	ResetScanSummary()
	refused := scanResult("10.0.0.1", "22")
	refused.Error = "connection refused"
	open := scanResult("10.0.0.1", "22")
	open.Open = true
	RecordScanResult(refused)
	RecordScanResult(open)
	RecordScanResult(refused)

	path := filepath.Join(t.TempDir(), "summary.json")
	if err := WriteScanSummary(path); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary ScanSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	record := summary.Targets["10.0.0.1"]
	if record.Tested != 1 {
		t.Errorf("tested = %d, want 1", record.Tested)
	}
	if record.Open != 1 || record.Closed != 0 {
		t.Errorf("open/closed = %d/%d, want 1/0", record.Open, record.Closed)
	}
}

func TestScanSummaryListsPerStatePorts(t *testing.T) {
	ResetScanSummary()
	open := scanResult("10.0.0.1", "443")
	open.Open = true
	refusedHigh := scanResult("10.0.0.1", "8080")
	refusedHigh.Error = "connection refused"
	refusedLow := scanResult("10.0.0.1", "80")
	refusedLow.Error = "connection refused"
	timeout := scanResult("10.0.0.1", "22")
	timeout.Error = "i/o timeout"
	denied := scanResult("10.0.0.1", "2375")
	denied.Error = "permission denied"
	unknown := scanResult("10.0.0.1", "9000")
	for _, result := range []*Result{open, refusedHigh, refusedLow, timeout, denied, unknown} {
		RecordScanResult(result)
	}

	path := filepath.Join(t.TempDir(), "summary.json")
	if err := WriteScanSummary(path); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary ScanSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	record := summary.Targets["10.0.0.1"]
	if record == nil {
		t.Fatal("missing target 10.0.0.1")
	}
	for _, test := range []struct {
		name string
		got  []string
		want []string
	}{
		{"open", record.OpenPorts, []string{"443"}},
		{"closed", record.ClosedPorts, []string{"80", "8080"}},
		{"filtered", record.FilteredPorts, []string{"22"}},
		{"error", record.ErrorPorts, []string{"2375"}},
		{"unknown", record.UnknownPorts, []string{"9000"}},
	} {
		if !reflect.DeepEqual(test.got, test.want) {
			t.Errorf("%s ports = %v, want %v", test.name, test.got, test.want)
		}
	}
}

func TestScanSummaryIgnoresNilResult(t *testing.T) {
	ResetScanSummary()
	RecordScanResult(nil)
	if got := len(summary().Targets); got != 0 {
		t.Fatalf("targets = %d, want 0", got)
	}
}
