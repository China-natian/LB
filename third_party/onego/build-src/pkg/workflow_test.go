package pkg

import (
	"testing"

	"github.com/chainreactors/utils/parsers"
)

func workflowBaseConfig() Config {
	return Config{
		GOGOConfig: &parsers.GOGOConfig{
			Ports: "top1",
			Mod:   Default,
		},
		RunnerOpt:       DefaultRunnerOption,
		PortProbe:       Default,
		IpProbe:         Default,
		Outputf:         "full",
		FileOutputf:     "json",
		OutputDelimiter: "\t",
	}
}

func TestWorkflowPrepareConfigKeepsNoScan(t *testing.T) {
	workflowConfig := (&Workflow{NoScan: true}).PrepareConfig(workflowBaseConfig())
	if !workflowConfig.NoScan {
		t.Fatal("workflow no-scan was dropped")
	}

	cliConfig := workflowBaseConfig()
	cliConfig.NoScan = true
	cliOverride := (&Workflow{}).PrepareConfig(cliConfig)
	if !cliOverride.NoScan {
		t.Fatal("CLI -n/--no override was dropped by workflow")
	}
}

func TestWorkflowPrepareConfigKeepsCLIOverrides(t *testing.T) {
	cliConfig := workflowBaseConfig()
	cliConfig.Mod = SUPERSMARTB
	cliConfig.NoSpray = true
	cliConfig.PortSpray = true
	cliConfig.AliveSprayMod = []string{"icmp"}
	cliConfig.OutputDelimiter = ","
	cliConfig.Filters = []string{"port==80"}
	cliConfig.FilterOr = true
	cliConfig.OutputFilters = [][]string{{"frame", "nginx", "::"}}

	prepared := (&Workflow{Mod: SMART}).PrepareConfig(cliConfig)
	if prepared.Mod != SUPERSMARTB {
		t.Fatalf("CLI mod override was dropped: %q", prepared.Mod)
	}
	if !prepared.NoSpray || !prepared.PortSpray {
		t.Fatal("CLI spray settings were dropped")
	}
	if !prepared.HasAlivedScan() {
		t.Fatal("CLI --ping was dropped")
	}
	if prepared.OutputDelimiter != "," || !prepared.FilterOr || len(prepared.Filters) != 1 || len(prepared.OutputFilters) != 1 {
		t.Fatal("CLI output/filter settings were dropped")
	}
}
