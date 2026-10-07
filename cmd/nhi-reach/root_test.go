package main

import (
	"io"
	"testing"
)

func TestFlagErrorsExitWith3(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"analyze", "--nope"}},
		{"bad int value", []string{"analyze", "--max-depth", "many"}},
		{"unknown flag on the root", []string{"--nope"}},
		{"missing flag value", []string{"analyze", "--target"}},
		{"bad fail-on value", []string{"analyze", "--fail-on", "maybe", "--from", "x"}},
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

func TestUnknownSubcommandExitsWith3(t *testing.T) {
	cases := [][]string{{"bogus"}, {"analyze", "extra", "args"}}
	for _, args := range cases {
		cmd := newRootCmd()
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("%v: the command accepted the arguments", args)
		}
		if code := exitCode(err); code != 3 {
			t.Errorf("%v: exit code %d, want 3: %v", args, code, err)
		}
	}
}

func TestNoArgumentsPrintsHelp(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs(nil)
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("root with no args: %v", err)
	}
}

func TestVersionCommandSucceeds(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
}
