package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ScanSummarySchema = "onego.scan-summary.v1"

// ScanTargetSummary is the machine-readable coverage record for one target.
// Tested counts unique numeric ports that reached a scan outcome; open_ports
// lists only ports confirmed open. Closed, filtered, error and unknown are
// distinct: only closed is evidence that a port is not listening.
type ScanTargetSummary struct {
	Tested    int            `json:"tested"`
	Open      int            `json:"open"`
	Closed    int            `json:"closed"`
	Filtered  int            `json:"filtered"`
	Error     int            `json:"error"`
	Unknown   int            `json:"unknown"`
	Excluded  int            `json:"excluded"`
	OpenPorts []string       `json:"open_ports"`
	Special   map[string]int `json:"special,omitempty"`

	ports map[string]string
}

type ScanSummary struct {
	Schema     string                        `json:"schema"`
	StartedAt  string                        `json:"started_at"`
	FinishedAt string                        `json:"finished_at,omitempty"`
	Targets    map[string]*ScanTargetSummary `json:"targets"`
}

var (
	summaryMu     sync.Mutex
	activeSummary *ScanSummary
)

func ResetScanSummary() {
	summaryMu.Lock()
	defer summaryMu.Unlock()
	activeSummary = &ScanSummary{
		Schema:    ScanSummarySchema,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Targets:   map[string]*ScanTargetSummary{},
	}
}

func summary() *ScanSummary {
	if activeSummary == nil {
		activeSummary = &ScanSummary{
			Schema:    ScanSummarySchema,
			StartedAt: time.Now().UTC().Format(time.RFC3339),
			Targets:   map[string]*ScanTargetSummary{},
		}
	}
	return activeSummary
}

// RecordScanResult is called once per dispatched target:port after the scan
// outcome is known. It is intentionally cheap and lock-protected because
// Dispatch runs concurrently.
func RecordScanResult(result *Result) {
	if result == nil {
		return
	}
	target := result.Ip
	if target == "" {
		target = "unknown"
	}
	summaryMu.Lock()
	defer summaryMu.Unlock()
	record := summary().Targets[target]
	if record == nil {
		record = &ScanTargetSummary{ports: map[string]string{}, Special: map[string]int{}}
		summary().Targets[target] = record
	}
	if result.Excluded {
		record.Excluded++
		return
	}
	port := strings.TrimSpace(result.Port)
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		if port != "" {
			record.Special[port]++
		}
		return
	}
	state := classifyResult(result)
	if previous, ok := record.ports[port]; !ok || stateRank(state) > stateRank(previous) {
		record.ports[port] = state
	}
}

func stateRank(state string) int {
	switch state {
	case "open":
		return 4
	case "closed":
		return 3
	case "filtered":
		return 2
	case "error":
		return 1
	default:
		return 0
	}
}

func classifyResult(result *Result) string {
	if result.Open {
		return "open"
	}
	message := strings.ToLower(result.Error)
	switch {
	case strings.Contains(message, "refused"):
		return "closed"
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline exceeded"):
		return "filtered"
	case strings.Contains(message, "permission denied"),
		strings.Contains(message, "no route"),
		strings.Contains(message, "unreachable"),
		strings.Contains(message, "host is down"),
		strings.Contains(message, "no such host"):
		return "error"
	}
	switch result.ErrStat {
	case 1:
		return "closed"
	case 2:
		return "filtered"
	case 3, 4, 5, 6:
		return "error"
	}
	return "unknown"
}

// WriteScanSummary writes the collected summary atomically. A missing file is
// safer than a fabricated "complete" claim, so callers must treat write errors
// as unknown coverage.
func WriteScanSummary(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	summaryMu.Lock()
	snapshot := summary()
	for _, record := range snapshot.Targets {
		finalize(record)
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	summaryMu.Unlock()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if directory != "" && directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(payload, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func finalize(record *ScanTargetSummary) {
	record.Tested = len(record.ports)
	record.Open = 0
	record.Closed = 0
	record.Filtered = 0
	record.Error = 0
	record.Unknown = 0
	record.OpenPorts = record.OpenPorts[:0]
	for port, state := range record.ports {
		switch state {
		case "open":
			record.Open++
			record.OpenPorts = append(record.OpenPorts, port)
		case "closed":
			record.Closed++
		case "filtered":
			record.Filtered++
		case "error":
			record.Error++
		default:
			record.Unknown++
		}
	}
	sort.Slice(record.OpenPorts, func(i, j int) bool {
		left, _ := strconv.Atoi(record.OpenPorts[i])
		right, _ := strconv.Atoi(record.OpenPorts[j])
		return left < right
	})
	if len(record.Special) == 0 {
		record.Special = nil
	}
}
