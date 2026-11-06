package core

import "testing"

func TestPrepareConfigKeepsNoScan(t *testing.T) {
	runner := Runner{}
	runner.NoScan = true
	runner.PrepareConfig()

	if !runner.Config.NoScan {
		t.Fatal("PrepareConfig dropped -n/--no")
	}
}
