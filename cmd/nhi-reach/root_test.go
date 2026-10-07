package main

import "testing"

func TestFlagErrorsExitWith3(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"analyze", "--nope"}},
		{"bad int value", []string{"analyze", "--max-depth", "many"}},
		{"unknown flag on the root", []string{"--nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("the command accepted the arguments")
			}
			if code := exitCode(err); code != 3 {
				t.Errorf("exit code %d, want 3: %v", code, err)
			}
		})
	}
}

func TestVersionCommandSucceeds(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
}
