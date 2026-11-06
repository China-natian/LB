package main

import (
	"github.com/chainreactors/onego/v2/engine"
	"github.com/chainreactors/onego/v2/pkg"
)

func main() {
	result := pkg.NewResult("127.0.0.1", "80")
	engine.Dispatch(pkg.DefaultRunnerOption, result)

	if result.Open {
		println(result.FullOutput())
	} else {
		println(result.GetTarget(), "close")
	}
}
