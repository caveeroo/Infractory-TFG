package runner

import (
	"context"
	"testing"
)

func TestExecRunnerUsesArgvWithoutShellInterpretation(t *testing.T) {
	r := ExecRunner{}
	got, err := r.Run(context.Background(), "/usr/bin/printf", "%s", "$(false); echo unsafe")
	if err != nil {
		t.Fatal(err)
	}
	if got.Stdout != "$(false); echo unsafe" {
		t.Fatalf("stdout = %q", got.Stdout)
	}
}
